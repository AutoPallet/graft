//! Transitive hash computation.
//!
//! Processes SCCs in reverse topological order (successors first) and
//! derives each node's `trans_hash` from a per-SCC **color refinement**
//! (partition refinement to the coarsest bisimulation — the same
//! fixpoint gold/lld ICF iterate toward, 1-WL in graph-isomorphism
//! terms):
//!
//! ```text
//! member_hash(n) = blake3(n.bytes || nominal_salt(n)?
//!                          || postcard(canonical_relocs(n)))
//! seed(n)  = blake3(member_hash(n) || slot stream: per reloc, in order,
//!            EXT | POOL | INTRA marker | OUT(trans_hash(target)))
//! color(n) = refine within the SCC until no round splits the
//!            partition:  c' = blake3(c(n) || c(t) for each INTRA
//!            slot target t, in slot order)
//! scc_hash(scc) = blake3(concat(sorted(color(m) for m in scc)))[:16]
//! trans_hash(n) = blake3(scc_hash(scc_of(n)) || color(n))[:16]
//! ```
//!
//! Why refinement and not "sorted member hashes + sorted successor
//! hashes" (the previous formula): inside an SCC there is no
//! well-founded recursion, so the old formula gave every member the
//! same transitive component and distinguished them only by their
//! one-hop member hash — whose reloc targets are canonicalized to
//! *bytes-only* fingerprints. Two same-SCC nodes whose difference sat
//! ≥2 hops away behind byte-identical intermediates collided (#42:
//! `<Adapter<Vec<u8>>/<Adapter<Stderr>>/<String> as fmt::Write>::
//! write_fmt` — identical wrapper text, identical literal bytes,
//! identical *vtable bytes*, genuinely different `write_str` targets —
//! ICF folded all three onto one vtable; null `self` in `spec_extend`
//! on hardware). Refinement propagates any intra-SCC distinction to
//! fixpoint: the vtables split on round 1 (their `write_str` targets'
//! seeds differ), literals on round 2, texts on round 3.
//!
//! Members that still tie at fixpoint are bisimilar — their reachable
//! graphs unroll to the same infinite tree — hence genuinely
//! interchangeable to any caller; equal trans_hash is exactly right
//! for them (the base-side ambiguity machinery in prune handles
//! same-hash-at-several-addresses). Cross-scan stability: the round
//! count is "first round with no split", a function of the SCC's own
//! content plus its (already-final) successor hashes — no global
//! iteration count leaks into unrelated hashes.
//!
//! Slot streams are reloc-ordered, NOT a sorted/deduped successor
//! set: wiring matters (a node whose slot 1 targets X and slot 2
//! targets Y is not the node with the slots swapped, even when X and
//! Y are byte-identical). POOL slots (string-pool section refs) carry
//! no target hash — the member hash already embeds the precise
//! per-string fingerprint, strings are leaves, and naming the pool's
//! first-string node here would couple callers to unrelated pool
//! reshuffles. Entry-targeted relocs are EXT: the trampoline cut
//! means callers depend on the entry's *address*, never its content.
//!
//! `nominal_salt` applies only to sections that are NOT content-
//! addressable (see `SectionInfo::content_addressable`): mutable data
//! (`.bss`, `.data`) and zero-size sections, whose bytes don't define
//! their identity. Without it, every zero-init static in the program
//! shares one trans_hash and positional resolution aliases distinct
//! variables onto one base address. The salt is the section's sorted
//! (symbol name, st_value) pairs — names with the `.llvm.<id>`
//! internal-linkage suffix stripped, so CGU repartitioning doesn't
//! churn the identity of an otherwise-unchanged static (which would
//! silently *duplicate* its state into the overlay).

use std::collections::HashMap;

use crate::graph::{Graph, SccResult};
use crate::elf::{CanonicalReloc, ParsedObject};

pub type TransHash = [u8; 16];

// Identity is keyed purely on `TransHash` (the section's transitive
// content hash). The former per-symbol `symhash` (name ‖ trans_hash) and
// its `stable_name_part` name-canonicalizer are gone: resolution is
// positional (section trans_hash → base address + in-section offset), and
// the only place a name still disambiguates — content-identical sections
// base placed at distinct addresses — is handled at prune time via the
// base.elf symtab snapshot. See `docs/14-identity-granularity.md`.

/// Per-node blake3 over the node's *identity bytes*: each segment's
/// content (respecting sub-ranges for per-string nodes) plus, for
/// non-content-addressable sections, the nominal salt. Aggregator nodes
/// own their contributors as segments, so this naturally captures the
/// merged-output content. This is the fingerprint that both the
/// trans_hash member-hash and the `ContentResolver` canonicalization
/// build on; exposed so the diagnostic dump (`debug_dump`) can reproduce
/// `compute` exactly instead of re-deriving it (and drifting).
///
/// The salt must be in here (not only in the SCC member hash): the
/// resolver rewrites reloc *targets* to these fingerprints, and without
/// it a referrer that swaps which of two same-content statics each
/// instruction touches would produce a byte-identical canonical reloc
/// list and an identical edge *set* — an invisible change.
pub fn node_identity_hashes(graph: &Graph, objects: &[ParsedObject]) -> Vec<blake3::Hash> {
    let salts = nominal_salts(objects);
    node_identity_hashes_with(graph, objects, &salts)
}

fn node_identity_hashes_with(
    graph: &Graph,
    objects: &[ParsedObject],
    salts: &HashMap<(u32, u32), Vec<u8>>,
) -> Vec<blake3::Hash> {
    use rayon::prelude::*;
    graph
        .nodes
        .par_iter()
        .map(|nm| {
            let mut h = blake3::Hasher::new();
            for seg in &nm.segments {
                let bytes = seg.bytes_in(&objects[seg.object as usize].sections);
                // Per-segment length framing: without it, multi-
                // segment (aggregator) nodes with different byte
                // boundaries could concatenate to identical streams
                // (review find: framing ambiguity).
                h.update(&(bytes.len() as u64).to_le_bytes());
                h.update(bytes);
                if seg.range.is_none()
                    && let Some(salt) = salts.get(&(seg.object, seg.section))
                {
                    h.update(salt);
                }
            }
            h.finalize()
        })
        .collect()
}

/// `(object, section) → identity salt` for every section that is NOT
/// content-addressable (mutable data, NOBITS, zero-size). The salt is a
/// marker plus the section's sorted (stripped symbol name, st_value
/// [, tu_id for locals]) tuples — nominal identity for sections whose
/// bytes don't define them. Content-addressable sections have no entry.
///
/// LOCAL symbol entries carry the defining object's tu_id: local names
/// are only unique per TU, and without it two C files' same-named
/// file-local statics (`static int counter;` in a.c and b.c) produced
/// identical salts — identical trans_hash for two DISTINCT mutable
/// variables, the exact M2 aliasing class the salt exists to prevent
/// (review find: nominal-salt TU-blindness). tu_id is
/// blake3(STT_FILE)[:8] — content-stable across rebuilds, unlike
/// object indexes. Global names are program-unique already; salting
/// them with tu_id would only churn identity when a static moves
/// between CGUs.
fn nominal_salts(objects: &[ParsedObject]) -> HashMap<(u32, u32), Vec<u8>> {
    use crate::elf::SymbolBind;
    let mut entries: HashMap<(u32, u32), Vec<(String, u64, Option<[u8; 8]>)>> = HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            if !sec.content_addressable() {
                entries.insert((oi as u32, si as u32), Vec::new());
            }
        }
        for sym in &obj.symbols {
            let Some(si) = sym.defining_section else { continue };
            if sym.name.is_empty() {
                continue;
            }
            if let Some(v) = entries.get_mut(&(oi as u32, si as u32)) {
                let tu = match sym.bind {
                    SymbolBind::Local => Some(obj.tu_id),
                    SymbolBind::Global | SymbolBind::Weak => None,
                };
                v.push((strip_llvm_suffix(&sym.name).to_string(), sym.value, tu));
            }
        }
    }
    entries
        .into_iter()
        .map(|(k, mut syms)| {
            syms.sort();
            syms.dedup();
            let mut blob = b"\0graft-nominal\0".to_vec();
            for (name, value, tu) in &syms {
                blob.extend_from_slice(&(name.len() as u32).to_le_bytes());
                blob.extend_from_slice(name.as_bytes());
                blob.extend_from_slice(&value.to_le_bytes());
                match tu {
                    Some(id) => {
                        blob.push(1);
                        blob.extend_from_slice(id);
                    }
                    None => blob.push(0),
                }
            }
            (k, blob)
        })
        .collect()
}

/// Strip rustc/LLVM's per-build internal-linkage suffix
/// (`foo.llvm.1234567890`) so the nominal salt doesn't churn when CGU
/// repartitioning renumbers it.
pub(crate) fn strip_llvm_suffix(name: &str) -> &str {
    match name.find(".llvm.") {
        Some(i) => &name[..i],
        None => name,
    }
}

/// Compute a `TransHash` for every node.
pub fn compute(
    objects: &[ParsedObject],
    graph: &Graph,
    scc: &SccResult,
) -> Vec<TransHash> {
    compute_detailed(objects, graph, scc).0
}

/// `compute` plus each node's containing-SCC hash — the diagnostic
/// dump prints both so divergence localizes to "member color" vs
/// "SCC transitive content" (its scc_hash column used to just repeat
/// trans_hash).
pub fn compute_detailed(
    objects: &[ParsedObject],
    graph: &Graph,
    scc: &SccResult,
) -> (Vec<TransHash>, Vec<TransHash>) {
    // Two-pass member hashing. Pass 1: per-node blake3 of the section
    // bytes plus, for non-content-addressable sections, the nominal
    // salt — a stable identity fingerprint that doesn't depend on
    // ordering or other build-time noise. Pass 2: full per-node hash
    // (identity bytes + canonicalized reloc list, where reloc target
    // names are rewritten to identity-fingerprints whenever the name
    // itself is build-time noise — see `canonicalize_target`).
    let salts = nominal_salts(objects);
    let identity_hashes = node_identity_hashes_with(graph, objects, &salts);
    let resolver = ContentResolver::build(objects, graph, &identity_hashes);

    use rayon::prelude::*;
    let member_input_hash: Vec<blake3::Hash> = graph
        .nodes
        .par_iter()
        .map(|nm| {
            let mut h = blake3::Hasher::new();
            for seg in &nm.segments {
                let obj = &objects[seg.object as usize];
                let sec = &obj.sections[seg.section as usize];
                let bytes = seg.bytes_in(&obj.sections);
                // Per-segment length framing (see node_identity_hashes).
                h.update(&(bytes.len() as u64).to_le_bytes());
                h.update(bytes);
                // Per-string segments (range = Some) have no relocs
                // of their own — string bytes don't reference
                // anything. Skip the section's relocs so each string
                // node's input-hash is invariant to relocs that
                // belong to other parts of the section.
                if seg.range.is_none() {
                    if let Some(salt) = salts.get(&(seg.object, seg.section)) {
                        h.update(salt);
                    }
                    let encoded = encode_relocs(&sec.relocs, seg.object, obj.tu_id, &resolver);
                    h.update(&encoded);
                }
            }
            h.finalize()
        })
        .collect();

    // Per-node dependency slot stream, reloc-ordered — the SAME
    // resolutions that built the graph edges (`reloc_targets`), with
    // the trampoline cut applied (entry target → EXT, address-only
    // dependency) and string-pool section refs collapsed to POOL (the
    // member hash already carries the precise per-string fingerprint).
    #[derive(Clone, Copy, PartialEq)]
    enum Slot {
        Node(u32),
        Ext,
        Pool,
    }
    use crate::graph::ResolvedTarget;
    let slots: Vec<Vec<Slot>> = graph
        .nodes
        .par_iter()
        .map(|nm| {
            let mut v = Vec::new();
            for seg in &nm.segments {
                if seg.range.is_some() {
                    continue; // per-string nodes own no relocs
                }
                let sec = &objects[seg.object as usize].sections[seg.section as usize];
                if sec.relocs.is_empty() {
                    continue;
                }
                let recorded = graph.reloc_targets.get(&(seg.object, seg.section));
                for r in &sec.relocs {
                    let slot = match recorded.and_then(|m| m.get(&(r.offset, r.r_type))) {
                        None | Some(ResolvedTarget::External) => Slot::Ext,
                        Some(&ResolvedTarget::Symbol { nid, .. })
                        | Some(&ResolvedTarget::Section { nid }) => {
                            if graph.entry_node == Some(nid) {
                                Slot::Ext
                            } else if r
                                .target_section
                                .is_some_and(|si| resolver.is_string_pool(seg.object, si))
                            {
                                Slot::Pool
                            } else {
                                Slot::Node(nid)
                            }
                        }
                    };
                    v.push(slot);
                }
            }
            v
        })
        .collect();

    // Reverse-topological SCC walk (leaves first): successors' final
    // trans_hashes exist before any SCC that references them is
    // seeded, so seeds are content-deterministic — no global iteration
    // count, no cross-scan instability.
    let mut th: Vec<TransHash> = vec![[0u8; 16]; graph.nodes.len()];
    let mut scch_of_node: Vec<TransHash> = vec![[0u8; 16]; graph.nodes.len()];

    for (sid, members) in scc.members.iter().enumerate() {
        let self_sid = sid as u32;
        let member_index: HashMap<u32, u32> = members
            .iter()
            .enumerate()
            .map(|(i, &n)| (n, i as u32))
            .collect();

        // Intra-SCC slot targets as member indexes, in slot order.
        let intra: Vec<Vec<u32>> = members
            .iter()
            .map(|&n| {
                slots[n as usize]
                    .iter()
                    .filter_map(|s| match s {
                        Slot::Node(t) if scc.scc_of_node[*t as usize] == self_sid => {
                            Some(member_index[t])
                        }
                        _ => None,
                    })
                    .collect()
            })
            .collect();

        let seeds: Vec<[u8; 32]> = members
            .iter()
            .map(|&n| {
                let mut h = blake3::Hasher::new();
                h.update(member_input_hash[n as usize].as_bytes());
                for s in &slots[n as usize] {
                    match s {
                        Slot::Ext => {
                            h.update(&[1u8]);
                        }
                        Slot::Pool => {
                            h.update(&[2u8]);
                        }
                        Slot::Node(t) => {
                            if scc.scc_of_node[*t as usize] == self_sid {
                                // Intra: position marker only; the
                                // refinement rounds supply the identity.
                                h.update(&[3u8]);
                            } else {
                                h.update(&[4u8]);
                                h.update(&th[*t as usize]);
                            }
                        }
                    }
                }
                *h.finalize().as_bytes()
            })
            .collect();

        // Color refinement: fold each intra slot target's previous
        // color in (slot order — wiring matters) until a round splits
        // nothing. New colors embed old colors, so the partition only
        // ever refines: ≤ |SCC| rounds, and the stop condition is a
        // function of this SCC's content alone.
        let mut colors = seeds;
        if members.len() > 1 {
            let mut distinct = count_distinct(&colors);
            loop {
                let refine = |i: usize| -> [u8; 32] {
                    let mut h = blake3::Hasher::new();
                    h.update(&colors[i]);
                    for &t in &intra[i] {
                        h.update(&colors[t as usize]);
                    }
                    *h.finalize().as_bytes()
                };
                let next: Vec<[u8; 32]> = if members.len() >= 256 {
                    (0..members.len()).into_par_iter().map(refine).collect()
                } else {
                    (0..members.len()).map(refine).collect()
                };
                let nd = count_distinct(&next);
                colors = next;
                if nd == distinct {
                    break;
                }
                distinct = nd;
            }
        }

        // scc_hash: order-invariant fold of the final colors (member
        // order in the object file must not matter).
        let mut sorted = colors.clone();
        sorted.sort_unstable();
        let mut h = blake3::Hasher::new();
        for c in &sorted {
            h.update(c);
        }
        let mut scch = [0u8; 16];
        scch.copy_from_slice(&h.finalize().as_bytes()[..16]);

        // Per-node trans_hash = scc_hash ‖ the member's refined color.
        // Members of a multi-node SCC are DISTINCT sections that base
        // places at distinct addresses (xtensa code ↔ literal pool
        // always cycle); the color keeps them distinguishable so
        // `by_section[th]` stays well-defined (M2). Members whose
        // colors tie at fixpoint are bisimilar — interchangeable — and
        // sharing a trans_hash routes them through prune's ambiguity
        // machinery, which is the correct treatment for true copies.
        for (i, &n) in members.iter().enumerate() {
            let mut h = blake3::Hasher::new();
            h.update(&scch);
            h.update(&colors[i]);
            let mut out = [0u8; 16];
            out.copy_from_slice(&h.finalize().as_bytes()[..16]);
            th[n as usize] = out;
            scch_of_node[n as usize] = scch;
        }
    }
    (th, scch_of_node)
}

fn count_distinct(colors: &[[u8; 32]]) -> usize {
    let mut s: Vec<&[u8; 32]> = colors.iter().collect();
    s.sort_unstable();
    s.dedup();
    s.len()
}

fn encode_relocs(
    relocs: &[CanonicalReloc],
    obj_idx: u32,
    tu_id: [u8; 8],
    resolver: &ContentResolver,
) -> Vec<u8> {
    // postcard gives us a stable, compact, order-preserving encoding of
    // the sorted reloc list. Relocs are pre-sorted by parse(). Before
    // encoding, rewrite each in-scope reloc target as a content
    // fingerprint of its target section so two scans of the same
    // source produce byte-identical encodings under any compiler-
    // internal renaming (CGU re-partitioning, .llvm.<id> suffix
    // drift, STT_SECTION-vs-symbol-target form changes).
    let canonical: Vec<CanonicalReloc> = relocs
        .iter()
        .map(|r| {
            let (target, addend) = resolver.canonicalize_reloc(r, obj_idx, tu_id);
            // target_section is deliberately cleared: physical section
            // indexes shift under CGU repartition; the canonicalized
            // `target` fingerprint is the hash-stable identity.
            CanonicalReloc {
                offset: r.offset,
                target,
                r_type: r.r_type,
                addend,
                target_section: None,
            }
        })
        .collect();
    postcard::to_allocvec(&canonical).unwrap_or_default()
}

/// Rewrite each reloc target name to a *content fingerprint* of the
/// section the target ultimately resolves to (when it's in-scope), so
/// `member_input_hash` is invariant under any build-time renaming
/// where the target's identity is content-defined.
///
/// Two scans of the same source can disagree on a reloc target's
/// name in three observed ways, none of which change semantics:
///
/// 1. **CGU re-partition shifts STT_SECTION targets.** When cargo
///    incremental re-emits a CGU, identical functions can be moved
///    to a different CGU with a different fingerprint, which changes
///    section names like `.text.<mangled>.llvm.<id>` and
///    `.rodata..Lanon.<fp>.<n>`.
/// 2. **STT_SECTION ↔ symbol reloc form.** A reloc that's a
///    section-target (`<section:...>`) in one CGU layout becomes a
///    global-symbol reloc when the target ends up in a different
///    object file under another layout.
/// 3. **`.llvm.<digits>` internal-linkage suffix drift.** rustc
///    appends a per-build suffix derived from CGU content; identical
///    functions get different suffixes when partitioning shifts.
///
/// All three become noise if we encode each in-scope target as
/// `@<bytes_hash>` instead of by its name. Out-of-scope targets
/// (genuine externals) keep their name, which is fine because the
/// SCC trans_hash already includes a separate external sentinel
/// count for those.
///
/// Public so the diagnostic dump (`debug_dump`) canonicalizes reloc
/// targets through the *same* code path `compute` uses, rather than a
/// hand-rolled copy that can (and did) drift — notably on string-pool
/// sub-ranges, where a copy keyed on whole-section bytes reports
/// fingerprints `compute` never produced.
pub struct ContentResolver {
    /// (object_idx, section_idx) → 8-byte content fingerprint, for
    /// section-target relocs. Keyed by the PHYSICAL index from
    /// `CanonicalReloc::target_section` — section names legally repeat
    /// within one object (two `.rwtext`s in the esp32s3 rcgu), so a
    /// name key can pick the wrong section. Pool sections (one physical
    /// section, many per-string LogicalNodes) are NOT in here — they
    /// live in `string_pool` instead.
    section: HashMap<(u32, u32), [u8; 8]>,
    /// (object_idx, section_idx) → sorted list of (offset, len,
    /// fingerprint) for SHF_MERGE | SHF_STRINGS sections. Used to
    /// canonicalize `<section:STR_POOL> + addend` refs to a specific
    /// string's fingerprint, so that anon refs to a particular
    /// string get a stable encoding regardless of which CGU's
    /// `.rodata.str1.1` happens to host the string in this build.
    string_pool: HashMap<(u32, u32), Vec<(u32, u32, [u8; 8])>>,
    /// Global symbol name → (defining-node content fingerprint, the
    /// symbol's section-relative st_value). The st_value is folded
    /// into the canonical addend so the encoding names the *byte the
    /// reloc resolves to*, not just the section: two byte-identical
    /// referrers to different symbols at different offsets of one
    /// multi-symbol section (the gcc/esp-idf several-functions-per-
    /// .text shape) are NOT interchangeable and must not hash equal.
    /// It also makes the symbol-reloc and section-reloc forms of the
    /// same reference canonicalize identically for st_value ≠ 0,
    /// which the section↔symbol invariance goal always required.
    global: HashMap<String, ([u8; 8], u64)>,
    /// (local symbol name, defining tu_id) → (defining-node content
    /// fingerprint, st_value). Locals can repeat by name across TUs;
    /// the tu_id disambiguates.
    local: HashMap<(String, [u8; 8]), ([u8; 8], u64)>,
    /// Local name → fingerprint regardless of TU — mirrors edge
    /// building's `locals_any_tu` fallback so hashing and resolution
    /// see the same world for cross-TU internal-linkage refs.
    /// Content-diverged names are absent (purged at graph build).
    local_any: HashMap<String, ([u8; 8], u64)>,
}

impl ContentResolver {
    pub fn build(
        objects: &[ParsedObject],
        graph: &Graph,
        bytes_hashes: &[blake3::Hash],
    ) -> Self {
        let _ = objects;
        let mut section = HashMap::new();
        let mut string_pool: HashMap<(u32, u32), Vec<(u32, u32, [u8; 8])>> = HashMap::new();
        for (nid, nm) in graph.nodes.iter().enumerate() {
            // Trampoline cut for section-form refs: the entry node's
            // sections don't get a fingerprint either (edges cut
            // Section targets to the entry the same way).
            if graph.entry_node == Some(nid as crate::graph::NodeId) {
                continue;
            }
            let mut h = [0u8; 8];
            h.copy_from_slice(&bytes_hashes[nid].as_bytes()[..8]);
            for seg in &nm.segments {
                match seg.range {
                    None => {
                        section.insert((seg.object, seg.section), h);
                    }
                    Some((off, len)) => {
                        string_pool
                            .entry((seg.object, seg.section))
                            .or_default()
                            .push((off, len, h));
                    }
                }
            }
        }
        // Name → fingerprint maps come FROM the SymbolIndex, not from
        // re-walking nodes: the index applies ld's bind precedence
        // (strong over weak) and the content tiebreak for multi-defs,
        // while the previous node-walk was last-write-wins in scan
        // order — hashing could track a definer that resolution never
        // binds to (review finds, task #44). One authority, per the
        // resolve-once doctrine.
        let fp8 = |nid: crate::graph::NodeId| -> [u8; 8] {
            let mut h = [0u8; 8];
            h.copy_from_slice(&bytes_hashes[nid as usize].as_bytes()[..8]);
            h
        };
        // Trampoline cut, mirrored: symbols defined on the entry node
        // are omitted, so refs to the entry canonicalize as its bare
        // NAME (stable, content-free) instead of a content
        // fingerprint. Edges and slot streams already cut these to
        // external sentinels; leaving the fingerprint here meant an
        // entry edit still dirtied every direct caller's member hash,
        // defeating the cut's documented purpose (review find, #45).
        // Symbols defined inside a split string pool attach to the
        // per-string sub-node, whose fingerprint origin is the STRING
        // start — but st_value is SECTION-relative. Rebase the stored
        // value to the node's own origin, or the canonical addend
        // double-counts the string's pool offset and the symbol-form
        // encoding diverges from section-form for the same byte
        // (review find: pooled-symbol st_value double-count).
        let rebased = |nid: crate::graph::NodeId, value: u64| -> u64 {
            match graph.nodes[nid as usize].segments.first().and_then(|s| s.range) {
                Some((off, _)) => value.saturating_sub(off as u64),
                None => value,
            }
        };
        let mut global = HashMap::new();
        for (name, nid, value) in graph.symbols.globals_full_iter() {
            if graph.entry_node == Some(nid) {
                continue;
            }
            global.insert(name.clone(), (fp8(nid), rebased(nid, value)));
        }
        let mut local = HashMap::new();
        for (key, nid, value) in graph.symbols.locals_full_iter() {
            if graph.entry_node == Some(nid) {
                continue;
            }
            local.insert(key.clone(), (fp8(nid), rebased(nid, value)));
        }
        // Cross-TU local refs resolve through locals_any_tu in edge
        // building; without the same fallback here they canonicalized
        // as their RAW names — which carry `.llvm.<id>` suffixes, the
        // exact CGU noise this canonicalization exists to erase
        // (review find: any_tu churn). Diverged names were purged
        // from the map at graph build, so every entry is content-
        // unique.
        let mut local_any = HashMap::new();
        for (name, nid, value) in graph.symbols.locals_any_tu_full_iter() {
            if graph.entry_node == Some(nid) {
                continue;
            }
            local_any.insert(name.clone(), (fp8(nid), rebased(nid, value)));
        }
        for v in string_pool.values_mut() {
            v.sort_by_key(|&(off, _, _)| off);
        }
        Self { section, string_pool, global, local, local_any }
    }

    /// Whether `(object, section)` is a split string pool (per-string
    /// LogicalNodes). Hash slot streams need this: pool refs carry no
    /// target hash of their own — the member hash already embeds the
    /// precise per-string fingerprint via `canonicalize_reloc`.
    pub fn is_string_pool(&self, object: u32, section: u32) -> bool {
        self.string_pool.contains_key(&(object, section))
    }

    pub fn canonicalize_reloc(
        &self,
        r: &CanonicalReloc,
        obj_idx: u32,
        tu_id: [u8; 8],
    ) -> (String, i64) {
        // Section-targeted reloc (physical index recorded by parse()).
        // Try the per-string pool first (pool and ordinary section maps
        // are mutually exclusive for any given section).
        if let Some(si) = r.target_section {
            if let Some(strings) = self.string_pool.get(&(obj_idx, si)) {
                if r.addend >= 0 {
                    let a = r.addend as u32;
                    let idx = strings.partition_point(|&(off, _, _)| off <= a);
                    if idx > 0 {
                        let (off, len, h) = strings[idx - 1];
                        if a < off + len {
                            return (format!("@{}", hex8(&h)), (a - off) as i64);
                        }
                    }
                }
                // Negative or out-of-range addend: no containing
                // entry. ld's own merged-offset lookup (BFD
                // `_bfd_merged_section_offset`, plain st_value+addend,
                // no pc-rel bias correction) would be equally lost —
                // GAS never reduces symbols against SEC_MERGE sections
                // to section+offset precisely so that lookup stays
                // unambiguous, so this shape is outside the toolchain
                // contract. Still, encode a whole-pool fingerprint,
                // NEVER the bare section name: `.rodata.str1.1` is
                // identical across objects, so the name collided
                // referrers of different strings and carried no
                // content — string edits were invisible to the hash
                // (review find, task #43).
                let mut h = blake3::Hasher::new();
                for &(off, len, fp) in strings {
                    h.update(&off.to_le_bytes());
                    h.update(&len.to_le_bytes());
                    h.update(&fp);
                }
                let mut fp8 = [0u8; 8];
                fp8.copy_from_slice(&h.finalize().as_bytes()[..8]);
                return (format!("@{}", hex8(&fp8)), r.addend);
            }
            if let Some(h) = self.section.get(&(obj_idx, si)) {
                return (format!("@{}", hex8(h)), r.addend);
            }
        }
        // Symbol targets: canonical addend = st_value + A — the byte
        // the reference actually resolves to, section-relative. Same
        // encoding a section-target form of this reference produces.
        if let Some(&(h, value)) = self.global.get(&r.target) {
            return (format!("@{}", hex8(&h)), value as i64 + r.addend);
        }
        if let Some(&(h, value)) = self.local.get(&(r.target.clone(), tu_id)) {
            return (format!("@{}", hex8(&h)), value as i64 + r.addend);
        }
        // Cross-TU internal-linkage ref: same fallback edge building
        // uses (locals_any_tu), so the fingerprint tracks the copy
        // resolution actually picked.
        if let Some(&(h, value)) = self.local_any.get(&r.target) {
            return (format!("@{}", hex8(&h)), value as i64 + r.addend);
        }
        // Out-of-scope target: keep the original name, stripped of
        // the `.llvm.<id>` per-build suffix (belt for names that leak
        // here with CGU fingerprints attached). It IS encoded into
        // member_input_hash (postcard of the canonical reloc list),
        // which is fine for genuine externals — crt/ROM/script names
        // are stable across scans.
        (strip_llvm_suffix(&r.target).to_string(), r.addend)
    }
}

fn hex8(bytes: &[u8; 8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
