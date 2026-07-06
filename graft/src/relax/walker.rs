//! The lazy overlay-side walk (docs/16 §8): verify / translate /
//! refuse, per anchor-target section, computed only for sections the
//! resolution frontier actually touches.
//!
//! Channel-2 positional anchors assume "input offset == output
//! offset" inside base's placed copy of a section. On xtensa, ld's
//! relaxation deletes and re-encodes bytes, so interior offsets
//! shift. A trans_hash match guarantees overlay's input bytes are
//! byte-identical to what base's link consumed, so the walk can run
//! entirely overlay-side: input view from the overlay's own object
//! bytes, output bytes from base.elf at the recorded placement.
//!
//! Per node, the verdict is cached as:
//!   - `Identity` — placed bytes equal input modulo reloc masks
//!     (every non-xtensa section; unrelaxed xtensa sections).
//!   - `Fates` — the DP-intersection's per-byte fate vector; only
//!     `Agreed(Kept)` offsets are translatable.
//!   - `Refused` — no source-grounded parse, or the node isn't
//!     walkable (aggregate, range, missing bytes). Refusal costs
//!     nothing off the frontier: it only surfaces when a query
//!     actually lands here (the fixpoint pre-pass then re-emits the
//!     target instead — see `overlay::compute_closure_fixpoint`).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use object::Object;

use crate::graph::NodeId;
use crate::hash::TransHash;
use crate::metadata::Placed;
use crate::resolve::Translation;
use crate::scan::ScanResult;

use super::verify::{LinkedImage, input_view, unique_symbol_addrs};
use super::{FateCell, Fate, engine, xtensa};

pub enum WalkEntry {
    /// Input offsets map 1:1 to output offsets.
    Identity,
    /// Per-input-byte fates from the DP intersection.
    Fates { fates: Vec<FateCell>, in_len: usize, out_len: usize },
    /// Nothing here is translatable.
    Refused(String),
}

pub struct Walker<'a> {
    scan: &'a ScanResult,
    by_section: &'a HashMap<TransHash, Placed>,
    image: LinkedImage<'a>,
    /// Unique-address symbols of base.elf — literal value pins for the
    /// xtensa input view (walk input, not a correctness check).
    lit_syms: HashMap<String, u64>,
    arch: object::Architecture,
    cache: RefCell<HashMap<NodeId, Rc<WalkEntry>>>,
}

impl<'a> Walker<'a> {
    pub fn new(
        scan: &'a ScanResult,
        by_section: &'a HashMap<TransHash, Placed>,
        base_elf_bytes: &'a [u8],
        arch: object::Architecture,
    ) -> Result<Self, String> {
        let image = LinkedImage::new(base_elf_bytes)?;
        let lit_syms = if arch == object::Architecture::Xtensa {
            let elf = object::File::parse(base_elf_bytes).map_err(|e| e.to_string())?;
            unique_symbol_addrs(&elf)
        } else {
            HashMap::new()
        };
        Ok(Walker { scan, by_section, image, lit_syms, arch, cache: RefCell::new(HashMap::new()) })
    }

    /// Translate input offset `q` (symbol value + reloc addend, which
    /// can compose past either end of the section) within node `nid`'s
    /// placed copy in base. `Err` is a refusal — the caller must
    /// re-emit or bail, never guess.
    pub fn query(&self, nid: NodeId, q: i128) -> Result<Translation, String> {
        let entry = self.entry(nid);
        match &*entry {
            WalkEntry::Identity => Ok(Translation::Identity),
            WalkEntry::Refused(why) => Err(why.clone()),
            WalkEntry::Fates { fates, in_len, out_len } => {
                if q < 0 || q > *in_len as i128 {
                    return Err(format!("offset {q:#x} outside section (len {in_len:#x})"));
                }
                // One-past-end (end brackets / one-past-end pointers)
                // maps to the placed end.
                if q == *in_len as i128 {
                    return Ok(Translation::Mapped(*out_len as u64));
                }
                match fates[q as usize] {
                    FateCell::Agreed(Fate::Kept(o)) => Ok(Translation::Mapped(u64::from(o))),
                    FateCell::Agreed(Fate::Deleted) => {
                        Err(format!("byte at {q:#x} was deleted by relaxation"))
                    }
                    FateCell::Agreed(Fate::Interior) => {
                        Err(format!("byte at {q:#x} is interior to a re-encoded instruction"))
                    }
                    FateCell::Ambiguous => {
                        Err(format!("min-cost parses disagree on the fate of byte {q:#x}"))
                    }
                }
            }
        }
    }

    /// Anchor byte-check (overlay-side `GRAFT_ANCHOR_VERIFY`): did node
    /// `nid`'s content reconcile with base's placed bytes? `Ok` when the
    /// walk verified it (Identity, or a source-grounded fate vector);
    /// `Err(why)` on refusal. Reuses the cached per-node verdict the
    /// channel-2 translation already computed, so it costs nothing beyond
    /// the first `query`.
    pub fn byte_check(&self, nid: NodeId) -> Result<(), String> {
        match &*self.entry(nid) {
            WalkEntry::Identity | WalkEntry::Fates { .. } => Ok(()),
            WalkEntry::Refused(why) => Err(why.clone()),
        }
    }

    fn entry(&self, nid: NodeId) -> Rc<WalkEntry> {
        if let Some(e) = self.cache.borrow().get(&nid) {
            return Rc::clone(e);
        }
        let e = Rc::new(self.compute(nid));
        self.cache.borrow_mut().insert(nid, Rc::clone(&e));
        e
    }

    fn compute(&self, nid: NodeId) -> WalkEntry {
        let th = self.scan.trans_hash[nid as usize];
        let Some(&Placed { addr, out_size }) = self.by_section.get(&th) else {
            return WalkEntry::Refused("no base placement for node".into());
        };
        let node = &self.scan.graph.nodes[nid as usize];
        let [seg] = node.segments.as_slice() else {
            return WalkEntry::Refused("multi-segment node is not walkable".into());
        };
        if seg.range.is_some() {
            return WalkEntry::Refused("range (merge-pool) node is not walkable".into());
        }
        let sec = &self.scan.objects[seg.object as usize].sections[seg.section as usize];
        if sec.bytes.is_empty() {
            // NOBITS / empty: nothing relaxes without bytes; identity
            // as long as base placed the same extent.
            return if sec.sh_size == out_size {
                WalkEntry::Identity
            } else {
                WalkEntry::Refused(format!(
                    "byteless section resized in base ({:#x} -> {out_size:#x})",
                    sec.sh_size
                ))
            };
        }
        let Some(out) = self.image.slice(addr, out_size) else {
            return WalkEntry::Refused(format!("no linked bytes at {addr:#x}+{out_size:#x}"));
        };
        let file = match object::File::parse(&*self.scan.inputs[seg.object as usize].bytes) {
            Ok(f) => f,
            Err(e) => return WalkEntry::Refused(format!("re-parse input object: {e}")),
        };
        let osec = match file.section_by_index(object::SectionIndex(seg.section as usize + 1)) {
            Ok(s) => s,
            Err(e) => return WalkEntry::Refused(format!("input section lookup: {e}")),
        };
        let input = match input_view(self.arch, &file, &osec, &self.lit_syms) {
            Ok(i) => i,
            Err(e) => return WalkEntry::Refused(format!("input extraction: {e}")),
        };
        if engine::masked_compare(&input, out).is_ok() {
            return WalkEntry::Identity;
        }
        if self.arch != object::Architecture::Xtensa {
            // Base-time verification recorded only byte-identical
            // placements on non-relaxing targets; a mismatch here means
            // the table and the image disagree.
            return WalkEntry::Refused(
                "placed bytes differ on a non-relaxing target (stale base table?)".into(),
            );
        }
        match engine::translations(&input, out, &xtensa::Xtensa) {
            Some(fates) => {
                WalkEntry::Fates { fates, in_len: input.bytes.len(), out_len: out.len() }
            }
            None => WalkEntry::Refused("no source-grounded parse (walk dirty/refused)".into()),
        }
    }
}
