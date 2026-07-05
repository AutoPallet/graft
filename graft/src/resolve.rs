//! Reloc disposition: the single place a kept section's relocation is
//! translated into what the pruned `.o` should emit.
//!
//! The scan resolved every reloc once (`graph::build` → `reloc_targets`,
//! wrap renaming included); this module turns those resolutions into
//! `RelocDisposition`s against base's section table. Prune is a dumb
//! rewriter: it wires up targets its own kept sections satisfy
//! (something only it can see, by symbol index) and asks `Resolver::
//! dispose` for everything else — it never resolves a name itself.
//! One resolution path, shared with the hash graph, means inclusion
//! (the closure walk) and resolution can't disagree — the bug class
//! behind both the original M2 channel-ordering bug and the xtensa
//! catch-all bail.
//!
//! The cascade (see `CLAUDE.md` § "prune's resolution channels"):
//!   1. target node is in the closure → UND; ld binds overlay's
//!      re-emitted copy.
//!   1b. target is a literal pool NOT in the closure → BAIL. The
//!      closure walk force-includes every pool a kept section
//!      references (`l32r` can't reach base's copy), so this firing
//!      means the walk and disposition disagree.
//!   2. target node's trans_hash is in base's table → anchor at
//!      `by_section[th] + value` (positional, no verify).
//!      2a. ambiguous hash + name uniquely in base.symtab → pin that
//!          copy + verify; unpinnable + mutable → bail; unpinnable +
//!          read-only/exec → representative copy.
//!   3. overlay saw a definition but base has no matching content and
//!      the closure didn't re-emit it → BAIL (stale-bind guard).
//!   4. no scan definition (External): base.symtab name → anchor +
//!      verify; ambiguous base name → bail; weak undef → weak UND
//!      (base resolved it to 0 too); otherwise bail.

use std::collections::{HashMap, HashSet};

use anyhow::{Result, bail};

use crate::graph::{NodeId, ResolvedTarget};
use crate::hash::TransHash;
use crate::metadata::Placed;

/// What prune should emit for one relocation it can't satisfy from its
/// own kept sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelocDisposition {
    /// Emit (or reuse) an UND symbol of this name; ld binds it to
    /// overlay's re-emitted copy (strong) or to 0 (weak undef mirror).
    /// `tls` mirrors the target node's SHF_TLS — ld rejects
    /// TLS-definition-vs-non-TLS-reference binds, so a re-emitted
    /// thread-local referenced cross-object needs an STT_TLS UND.
    Und { name: String, weak: bool, tls: bool },
    /// Anchor at `vaddr`: prune emits an UND reference to
    /// `__graft_assumed_<hex>`, and the overlay run's synthetic base-map
    /// object defines that name — as a section symbol inside a map
    /// section placed at base's layout (positional content), or SHN_ABS
    /// when the vaddr lies outside every base PT_LOAD (true constants:
    /// ROM/PROVIDE addresses). The reloc's own addend rides along.
    /// `tls` marks vaddrs inside base's PT_TLS template: their map
    /// sections carry SHF_TLS and the UND reference must be STT_TLS so
    /// ld accepts TLS-flavored relocs and recomputes TP offsets from
    /// the (identical) template geometry. `verify_name = Some` for
    /// resolutions that assume base.elf's symtab address — overlay
    /// post-link verifies the name landed there. `addend = Some(a)`
    /// REPLACES the reloc's own addend in the pruned object: walk-
    /// translated anchors fold `value + addend` into a single output
    /// offset (the input-space addend must not be re-applied on top).
    Anchor { vaddr: u64, tls: bool, verify_name: Option<String>, addend: Option<i64> },
}

/// One reloc prune couldn't satisfy internally, described for
/// disposition. `target_name = None` for STT_SECTION refs (their
/// offset rides in the addend).
pub struct RelocQuery<'a> {
    /// 0-based index of the (kept) section the reloc lives in.
    pub section0: u32,
    pub offset: u64,
    pub r_type: u32,
    /// The reloc's own addend. Channel 2 composes it with the symbol
    /// value to query the walk (the target BYTE is what must be
    /// translated); every other channel lets it ride unchanged.
    pub addend: i64,
    pub target_name: Option<&'a str>,
    /// True if the referencing object's symtab entry for the target is
    /// STB_WEAK — the weak-undef mirror channel keys on this.
    pub weak_ref: bool,
    /// For diagnostics.
    pub from_section: &'a str,
}

/// Disposition callback handed to `prune_object`. Borrows the overlay
/// run's `Resolver` (tests substitute a fixture closure).
pub type DisposeFn<'a> = dyn Fn(&RelocQuery<'_>) -> Result<RelocDisposition> + 'a;

/// Where an input-space offset lands inside base's placed copy of a
/// section (`relax::walker::Walker::query`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Translation {
    /// Input offsets map 1:1 to output offsets — non-relaxing targets
    /// and unrelaxed xtensa sections.
    Identity,
    /// The queried input offset survives at this output offset.
    Mapped(u64),
}

/// Positional offset translation for channel 2 — `(node, value +
/// addend) -> Translation`. `Err` is a refusal: the pre-pass should
/// have re-emitted the target, so disposition treats it as fatal.
pub type TranslateFn<'a> = dyn Fn(NodeId, i128) -> Result<Translation, String> + 'a;

/// The non-relaxing default: every recorded placement was byte-
/// verified at base time, so offsets map 1:1.
pub fn identity_translate(_: NodeId, _: i128) -> Result<Translation, String> {
    Ok(Translation::Identity)
}

/// Everything disposition needs, as flat borrowed tables (directly
/// constructible in tests).
pub struct Resolver<'a> {
    /// Per-node identity hashes (`ScanResult::trans_hash`).
    pub trans_hash: &'a [TransHash],
    /// The scan's per-reloc resolutions (`Graph::reloc_targets`).
    pub reloc_targets: &'a HashMap<(u32, u32), HashMap<(u64, u32), ResolvedTarget>>,
    /// Closure membership by NODE — not by trans_hash — so two
    /// content-identical nodes (one re-emitted, one not) can't be
    /// confused.
    pub closure_nids: &'a HashSet<NodeId>,
    /// Nodes backed by non-content-addressable sections (mutable data /
    /// NOBITS / zero-size), by trans_hash — gates the
    /// representative-copy shortcut for ambiguous hashes.
    pub mutable_ths: &'a HashSet<TransHash>,
    /// `--wrap=<sym>` names. The scan's recorded resolutions already
    /// applied the rename; this re-applies it to the *emitted* name
    /// (UND / verify) so ld sees the wrapper.
    pub wrapped: &'a HashSet<String>,
    /// Base's content-keyed section table (`trans_hash → placement`).
    pub by_section: &'a HashMap<TransHash, Placed>,
    /// Hashes base placed at multiple distinct addresses.
    pub ambiguous_sections: &'a HashSet<TransHash>,
    /// Base.elf symtab snapshot (unique-address names only).
    pub by_name: &'a HashMap<String, u64>,
    /// Names base defined at multiple distinct addresses.
    pub by_name_ambiguous: &'a HashSet<String>,
    /// Channel-2 positional offset translation (the lazy walk).
    /// `identity_translate` everywhere except xtensa overlay runs.
    pub translate: &'a TranslateFn<'a>,
    /// Literal-pool nodes (xtensa; empty elsewhere). Pools always
    /// travel with the code that references them — `l32r` reaches
    /// −256KB backward only, so a base pool address is out of range
    /// for re-emitted overlay code. Every reloc we dispose lives in a
    /// kept (closure) section, and the closure walk force-includes
    /// pools its members reference, so a pool target reaching channel
    /// 2 is an invariant violation, not a resolvable case.
    pub pool_nids: &'a HashSet<NodeId>,
    /// Base's PT_TLS template span `[start, end)`, if base has one.
    /// Anchors whose vaddr falls inside are TLS anchors (template
    /// vaddrs — see `build_section_table`'s translation).
    pub tls_range: Option<(u64, u64)>,
    /// Nodes backed by SHF_TLS sections — channel 1's UND emissions
    /// need the symbol type to match the (TLS) definition.
    pub tls_nids: &'a HashSet<NodeId>,
}

impl<'a> Resolver<'a> {
    fn is_tls(&self, vaddr: u64) -> bool {
        self.tls_range.is_some_and(|(s, e)| vaddr >= s && vaddr < e)
    }

    /// Dispose one reloc from object `obj`. See module docs for the
    /// cascade.
    pub fn dispose(&self, obj: u32, q: &RelocQuery<'_>) -> Result<RelocDisposition> {
        let resolved = self
            .reloc_targets
            .get(&(obj, q.section0))
            .and_then(|m| m.get(&(q.offset, q.r_type)))
            .copied()
            .unwrap_or(ResolvedTarget::External);

        // The scan resolved through the wrap rename; emit/look up the
        // same name ld will see.
        let lookup_name: Option<String> = q.target_name.map(|n| {
            if self.wrapped.contains(n) { format!("__wrap_{n}") } else { n.to_string() }
        });

        match resolved {
            ResolvedTarget::Symbol { nid, value } => {
                self.dispose_node(nid, value, q.addend, lookup_name.as_deref(), q.from_section)
            }
            ResolvedTarget::Section { nid } => {
                // A section ref carries no name; the addend holds the
                // offset (and rides unchanged unless walk-translated).
                self.dispose_node(nid, 0, q.addend, None, q.from_section)
            }
            ResolvedTarget::External => {
                self.dispose_external(lookup_name.as_deref(), q.weak_ref, q.from_section)
            }
        }
    }

    fn dispose_node(
        &self,
        nid: NodeId,
        value: u64,
        addend: i64,
        name: Option<&str>,
        from_section: &str,
    ) -> Result<RelocDisposition> {
        let th = self.trans_hash[nid as usize];
        if self.closure_nids.contains(&nid) {
            // (1) re-emitted by overlay. Needs a name for ld to bind;
            // a section ref into a closure section is always satisfied
            // intra-object (closure sections are kept per-object), so
            // prune resolves it internally and never asks us.
            let Some(name) = name else {
                bail!(
                    "reloc in {from_section}: section target is in the closure but \
                     not kept in this object — closure bookkeeping bug"
                );
            };
            return Ok(RelocDisposition::Und {
                name: name.to_string(),
                weak: false,
                tls: self.tls_nids.contains(&nid),
            });
        }
        if self.pool_nids.contains(&nid) {
            bail!(
                "reloc in {from_section}: {} is a literal pool that was not re-emitted \
                 — pools must travel with their referencing code (closure walk bug).",
                name.unwrap_or("<section ref>"),
            );
        }
        if let Some(&Placed { addr: sec_addr, .. }) = self.by_section.get(&th) {
            if self.ambiguous_sections.contains(&th) {
                if let Some(name) = name
                    && let Some(&addr) = self.by_name.get(name)
                {
                    // (2a) several byte-identical copies; the name pins
                    // base's exact one (an output-space symtab address —
                    // no walk translation). Verify post-link.
                    return Ok(RelocDisposition::Anchor {
                        vaddr: addr,
                        tls: self.is_tls(addr),
                        verify_name: Some(name.to_string()),
                        addend: None,
                    });
                }
                if self.mutable_ths.contains(&th) {
                    bail!(
                        "reloc in {from_section}: {} resolves to mutable section content \
                         base placed at multiple addresses, and no name can pin one copy \
                         — refusing to alias distinct variables.",
                        name.unwrap_or("<section ref>"),
                    );
                }
                // Read-only/exec interchangeable copies → representative.
                return self.positional_anchor(nid, sec_addr, value, addend, name, from_section);
            }
            // (2) clean positional content match.
            return self.positional_anchor(nid, sec_addr, value, addend, name, from_section);
        }
        // (3) overlay has a definition whose content is NOT in base and
        // the closure didn't re-emit it — binding to any base address
        // would run stale code.
        bail!(
            "reloc in {from_section}: {} has overlay content that differs from base \
             but is not in the closure — refusing to bind to a stale address. \
             Likely a closure / scan-discovery bug.",
            name.unwrap_or("<section ref>"),
        );
    }

    /// Channels 2 / 2-representative: anchor at base's placed copy,
    /// translating the interior offset through the lazy walk. The walk
    /// queries the target BYTE — `value + addend` — because that is
    /// the input-space position whose output-space home we need; a
    /// translated anchor therefore folds the addend in and overrides
    /// the emitted addend to 0 (`S + A = (sec_addr + T) + 0`).
    fn positional_anchor(
        &self,
        nid: NodeId,
        sec_addr: u64,
        value: u64,
        addend: i64,
        name: Option<&str>,
        from_section: &str,
    ) -> Result<RelocDisposition> {
        let q = i128::from(value) + i128::from(addend);
        match (self.translate)(nid, q) {
            Ok(Translation::Identity) => Ok(RelocDisposition::Anchor {
                vaddr: sec_addr + value,
                tls: self.is_tls(sec_addr + value),
                verify_name: None,
                addend: None,
            }),
            Ok(Translation::Mapped(t)) => {
                let vaddr = sec_addr + t;
                Ok(RelocDisposition::Anchor {
                    vaddr,
                    tls: self.is_tls(vaddr),
                    verify_name: None,
                    addend: Some(0),
                })
            }
            // The fixpoint pre-pass re-emits refused targets before
            // prune ever disposes, so a refusal here is a walk/dispose
            // disagreement — refuse loudly, never guess an offset.
            Err(why) => bail!(
                "reloc in {from_section}: {} resolves into base's relaxed copy but the walk refused to translate offset {q:#x}: {why} (pre-pass gap)",
                name.unwrap_or("<section ref>"),
            ),
        }
    }

    fn dispose_external(
        &self,
        lookup_name: Option<&str>,
        weak_ref: bool,
        from_section: &str,
    ) -> Result<RelocDisposition> {
        let Some(lookup_name) = lookup_name else {
            bail!(
                "reloc in {from_section}: section target has no scan node — \
                 graft can't pin its base address"
            );
        };
        if let Some(&addr) = self.by_name.get(lookup_name) {
            // (4) base resolved it (script absolute, PROVIDE, ROM, crt,
            // aggregator bracket, prebuilt-lib symbol) → anchor + verify.
            // Output-space symtab address: no walk translation.
            return Ok(RelocDisposition::Anchor {
                vaddr: addr,
                tls: self.is_tls(addr),
                verify_name: Some(lookup_name.to_string()),
                addend: None,
            });
        }
        if self.by_name_ambiguous.contains(lookup_name) {
            bail!(
                "reloc in {from_section}: {lookup_name} is defined at multiple distinct \
                 addresses in base.elf — can't disambiguate without a tu_id \
                 (upstream scan gap)."
            );
        }
        // Weak undef: base resolved it to 0 (it's absent from
        // base.symtab) — mirror with a weak UND so ld writes 0 here too.
        if weak_ref {
            return Ok(RelocDisposition::Und {
                name: lookup_name.to_string(),
                weak: true,
                tls: false,
            });
        }
        bail!(
            "reloc in {from_section}: can't resolve {lookup_name} — not in overlay \
             scan, not in base's section table, not in base.symtab snapshot. \
             Likely an upstream scan-discovery bug."
        );
    }
}
