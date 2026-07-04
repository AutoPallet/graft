//! Cross-object forward-reloc graph + Tarjan SCC.
//!
//! Nodes = sections, numbered globally (flat index across all objects).
//! Edges = outgoing relocs, resolved through the symbol index. External
//! targets (not defined in our inputs) are *not* represented as nodes;
//! they're tracked per-section so the hash pass can fold them in as
//! sentinel hashes.

use std::collections::{HashMap, HashSet};
use rustc_hash::FxHashMap;

use crate::elf::{ParsedObject, SymbolBind};
use object::elf::SHF_ALLOC;

pub type NodeId = u32;

/// Identifies a symbol across all objects. Globals key on `name`; locals
/// on `(name, tu_id)` because the same mangled local-symbol name can
/// appear in multiple TUs. Values carry `(defining node, st_value)` —
/// the symbol's section-relative offset, which positional resolution
/// adds to the node's recovered base address.
#[derive(Debug, Default)]
pub struct SymbolIndex {
    globals: FxHashMap<String, (NodeId, u64)>,
    locals: FxHashMap<(String, [u8; 8]), (NodeId, u64)>,
    /// First-write-wins across TUs — fallback for STB_LOCAL names
    /// referenced from a different TU than the defining one (rust
    /// internal-linkage symbols accessed cross-CGU). Safe because
    /// identical content → identical trans_hash → an interchangeable
    /// copy.
    locals_any_tu: FxHashMap<String, (NodeId, u64)>,
}

impl SymbolIndex {
    pub fn resolve_global(&self, name: &str) -> Option<(NodeId, u64)> {
        self.globals.get(name).copied()
    }
    pub fn resolve_local(&self, name: &str, tu_id: [u8; 8]) -> Option<(NodeId, u64)> {
        self.locals.get(&(name.to_string(), tu_id)).copied()
    }
    pub fn resolve_local_any_tu(&self, name: &str) -> Option<(NodeId, u64)> {
        self.locals_any_tu.get(name).copied()
    }
    /// One unified resolution order for *every* consumer (edge building,
    /// reloc disposition): global → local-in-TU → local-any-TU. A single
    /// code path means hashing and resolution cannot disagree about what
    /// a name refers to.
    pub fn resolve(&self, name: &str, tu_id: [u8; 8]) -> Option<(NodeId, u64)> {
        self.resolve_global(name)
            .or_else(|| self.resolve_local(name, tu_id))
            .or_else(|| self.resolve_local_any_tu(name))
    }
    pub fn globals_iter(&self) -> impl Iterator<Item = (&String, NodeId)> {
        self.globals.iter().map(|(n, &(v, _))| (n, v))
    }
}

/// Where one relocation points, resolved once at scan time and reused
/// by every downstream consumer (hash canonicalization sees the same
/// world via `ContentResolver`; prune receives dispositions derived
/// from these). See `docs/14-identity-granularity.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedTarget {
    /// Symbol-targeted reloc: the defining node plus the symbol's
    /// section-relative value (the `S` in `S + A`).
    Symbol { nid: NodeId, value: u64 },
    /// Section-targeted reloc (`<section:…>`): the section's node (the
    /// first per-string node for SHF_MERGE pools); the reloc's addend
    /// carries the in-section offset.
    Section { nid: NodeId },
    /// Not defined by any scan input (crt/script/ROM/prebuilt names).
    External,
}

#[derive(Debug)]
pub struct Graph {
    /// One entry per LogicalNode. Each node owns 1+ physical segments
    /// passed to the linker if included; "aggregator" nodes additionally
    /// carry an `aggregator_id` and `bracket_symbols` for linker-merged
    /// outputs (`.init_array`, `.eh_frame`, …) whose contributor input
    /// sections are folded into one node.
    pub nodes: Vec<NodeMeta>,
    /// `edges[n]` = list of internal destinations from node `n`,
    /// derived from each segment's outgoing relocs.
    pub edges: Vec<Vec<NodeId>>,
    /// Count of external (unresolved-in-our-inputs) targets for each
    /// node. The hash pass folds these in as `[0u8; 16]` sentinels.
    pub external_edge_counts: Vec<u32>,
    pub symbols: SymbolIndex,
    /// Per-section reloc resolutions: `(object, section) → (reloc
    /// offset, r_type) → target`. Wrap renaming (`--wrap`) is already
    /// applied. Overlay derives prune's reloc dispositions from this —
    /// the same resolution that built `edges` — so inclusion (closure)
    /// and resolution can't drift.
    pub reloc_targets: HashMap<(u32, u32), HashMap<(u64, u32), ResolvedTarget>>,
    /// The trampoline target's node, if the entry symbol resolved.
    /// `reloc_targets` records the true node for entry-targeted relocs
    /// (prune needs the real resolution), but *edges* fold them into
    /// external sentinels — consumers that re-derive per-reloc
    /// dependencies from `reloc_targets` (hash slot streams) must apply
    /// the same cut, so the cut point lives here, not in each consumer.
    pub entry_node: Option<NodeId>,
}

/// A LogicalNode is the unit of inclusion: closure, hashing, and SCC
/// formation all operate on LogicalNodes. Each owns one or more
/// physical input sections (`segments`) that are passed verbatim to the
/// linker if the node is included.
///
/// Aggregator nodes (e.g. the one node representing the linker-merged
/// `.init_array` output) own all contributing input sections as
/// segments and additionally define bracket symbols (`__init_array_start`,
/// `__init_array_end`) whose addresses live in base.elf's symtab.
#[derive(Debug, Clone)]
pub struct NodeMeta {
    /// Physical input sections to ship to the linker if this node is
    /// included. Always non-empty.
    pub segments: Vec<SegmentRef>,
    /// Stable identifier from `synthetic::Aggregator::id`, set for
    /// aggregator nodes (matches the merged-output section name in
    /// base.elf). `None` for ordinary nodes.
    pub aggregator_id: Option<&'static str>,
    /// Every symbol defined by this node — both symbols originating
    /// in any of its `segments` and synthesized bracket symbols
    /// (aggregator nodes only; e.g. `__init_array_start`).
    pub defined_symbols: Vec<DefinedSymbol>,
}

#[derive(Debug, Clone)]
pub struct DefinedSymbol {
    pub name: String,
    pub bind: SymbolBind,
    /// `Some(tu_id)` for symbols originating in a parsed input
    /// section (carries the defining object's `tu_id` for STB_LOCAL
    /// disambiguation). `None` for synthesized bracket symbols.
    pub tu_id: Option<[u8; 8]>,
    /// Section-relative st_value (0 for synthesized bracket symbols).
    pub value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SegmentRef {
    pub object: u32,
    pub section: u32,
    /// Sub-range within the section, used by per-string nodes from
    /// SHF_MERGE | SHF_STRINGS pools. `None` means "whole section".
    /// The linker still receives the entire physical section (we
    /// can't ship a partial section), so this only affects hashing
    /// and reloc-target canonicalization — *not* what's emitted.
    pub range: Option<(u32, u32)>,
}

impl SegmentRef {
    pub fn whole(object: u32, section: u32) -> Self {
        Self { object, section, range: None }
    }
    pub fn substring(object: u32, section: u32, offset: u32, len: u32) -> Self {
        Self { object, section, range: Some((offset, len)) }
    }
    pub fn bytes_in<'a>(&self, sections: &'a [crate::elf::SectionInfo]) -> &'a [u8] {
        let bytes = &sections[self.section as usize].bytes;
        match self.range {
            None => bytes,
            Some((off, len)) => &bytes[off as usize..(off + len) as usize],
        }
    }
}

impl NodeMeta {
    /// Convenience constructor for an ordinary single-segment node
    /// (caller populates `defined_symbols`).
    pub fn segment(object: u32, section: u32) -> Self {
        Self {
            segments: vec![SegmentRef::whole(object, section)],
            aggregator_id: None,
            defined_symbols: Vec::new(),
        }
    }
    pub fn is_aggregator(&self) -> bool {
        self.aggregator_id.is_some()
    }
}

/// Build the forward-reloc graph across a set of parsed objects.
///
/// `entry_symbol` names graft's single trampoline target (the base /
/// overlay cut point). Edges whose *target* is the entry node are folded
/// in as external sentinels rather than internal edges, so the entry's
/// content does NOT propagate into its callers' trans_hashes. This is
/// sound — and necessary — because the trampoline redirects the entry's
/// *address*: base's callers of the entry are reused verbatim and stay
/// correct regardless of the overlay's new entry content, so an edit to
/// the entry must not make its callers (e.g. `main`, the IRAM runtime
/// that calls `main`) look "changed". A caller that *inlines* part of the
/// entry instead has different bytes, which `bytes_hash`/`mih` already
/// capture, so the cut hides nothing real. See
/// `docs/14-identity-granularity.md`.
///
/// `wrapped` is the `--wrap=<sym>` set: a reloc to `<sym>` is resolved
/// as `__wrap_<sym>` — both for edges (the semantic dependency is on
/// the wrapper's content) and for the recorded `reloc_targets`, exactly
/// as ld redirects the reference at link time.
pub fn build(
    objects: &[ParsedObject],
    entry_symbol: Option<&str>,
    wrapped: &HashSet<String>,
) -> Graph {
    // First, classify each allocated input section into one of three
    // shapes:
    //   - Aggregator contributor (`.init_array.NN`, etc.): folded into
    //     a single aggregator node.
    //   - String pool (`SHF_MERGE | SHF_STRINGS`): split into one
    //     LogicalNode per NUL-terminated string. Per-string nodes
    //     give anon refs to a specific string a stable content
    //     fingerprint independent of which CGU the string lives in
    //     (cargo's CGU repartitioning shuffles strings between
    //     `.rodata.str1.1` sections without changing their bytes).
    //   - Ordinary: one LogicalNode per section.
    let mut contributor_to_agg: HashMap<(u32, u32), &'static crate::synthetic::Aggregator> =
        HashMap::new();
    let mut merge_pool_entries: HashMap<(u32, u32), Vec<(u32, u32)>> = HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            if sec.sh_flags & u64::from(SHF_ALLOC) == 0 { continue; }
            // Aggregator-contributor classification first (mutually
            // exclusive with string-pool in practice).
            let mut is_contributor = false;
            for agg in crate::synthetic::AGGREGATORS {
                if agg.contributor.matches(&sec.name) {
                    contributor_to_agg.insert((oi as u32, si as u32), agg);
                    is_contributor = true;
                    break;
                }
            }
            if is_contributor { continue; }
            // Merge-pool classification. ld deduplicates and reorders
            // these at *entry* granularity across all inputs, so a
            // whole-section identity (and a whole-section base address)
            // doesn't exist post-link — the map oracle caught
            // `.rodata.cstN` sections "recovered" at one symbol's idea
            // of the base while the map disagreed. Split into one node
            // per entry, mirroring the merge unit ld actually uses:
            //   - SHF_MERGE|SHF_STRINGS → NUL-terminated strings
            //     (sh_entsize = 1, universally true for rust-emitted
            //     `.rodata.str1.1`).
            //   - SHF_MERGE alone → fixed sh_entsize chunks
            //     (`.rodata.cst8/16/32`). Sections whose size isn't a
            //     multiple of the entsize are treated as ordinary —
            //     ld refuses to merge those too.
            if sec.sh_flags & (SHF_MERGE | SHF_STRINGS) == (SHF_MERGE | SHF_STRINGS) {
                let strings = split_nul_terminated(&sec.bytes);
                if !strings.is_empty() {
                    merge_pool_entries.insert((oi as u32, si as u32), strings);
                }
            } else if sec.sh_flags & u64::from(SHF_MERGE) != 0
                && sec.sh_entsize > 0
                && !sec.bytes.is_empty()
                && sec.bytes.len() as u64 % sec.sh_entsize == 0
            {
                let n = sec.sh_entsize as u32;
                let entries: Vec<(u32, u32)> = (0..sec.bytes.len() as u32 / n)
                    .map(|i| (i * n, n))
                    .collect();
                merge_pool_entries.insert((oi as u32, si as u32), entries);
            }
        }
    }

    // Build LogicalNodes.
    //   - Ordinary single-segment nodes for non-contributor,
    //     non-pool sections (`node_of[(oi, si)] = nid`).
    //   - Per-string nodes for string-pool sections
    //     (`string_node_of[(oi, si, offset)] = nid`); we *also*
    //     register the string-pool section in `node_of` to point at
    //     the *first* string node, so that any code path that still
    //     wants a section-level NodeId (e.g. a reloc with addend
    //     mid-string falling back from the string-table lookup) gets
    //     a valid answer.
    //   - Aggregator nodes built last, owning their contributor
    //     segments.
    let mut nodes: Vec<NodeMeta> = Vec::new();
    let mut node_of: HashMap<(u32, u32), NodeId> = HashMap::new();
    let mut string_node_of: HashMap<(u32, u32, u32), NodeId> = HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            if sec.sh_flags & u64::from(SHF_ALLOC) == 0 { continue; }
            if contributor_to_agg.contains_key(&(oi as u32, si as u32)) { continue; }
            if let Some(strings) = merge_pool_entries.get(&(oi as u32, si as u32)) {
                // One LogicalNode per string. All share the same
                // underlying section but with distinct sub-ranges.
                let mut first_nid: Option<NodeId> = None;
                for &(off, len) in strings {
                    let nid = nodes.len() as NodeId;
                    nodes.push(NodeMeta {
                        segments: vec![SegmentRef::substring(oi as u32, si as u32, off, len)],
                        aggregator_id: None,
                        defined_symbols: Vec::new(),
                    });
                    string_node_of.insert((oi as u32, si as u32, off), nid);
                    first_nid.get_or_insert(nid);
                }
                if let Some(nid) = first_nid {
                    node_of.insert((oi as u32, si as u32), nid);
                }
                continue;
            }
            let nid = nodes.len() as NodeId;
            nodes.push(NodeMeta::segment(oi as u32, si as u32));
            node_of.insert((oi as u32, si as u32), nid);
        }
    }
    for agg in crate::synthetic::AGGREGATORS {
        // Gather contributor segments for this aggregator. Sort by
        // (content_hash, object_idx, section_idx) so independently-
        // built scans whose object iteration order differs (rlibs
        // re-emit member ordering nondeterministically) still produce
        // the same segment list.
        let mut contributor_segs: Vec<(SegmentRef, [u8; 32])> = Vec::new();
        for (&(oi, si), &owning_agg) in &contributor_to_agg {
            if !std::ptr::eq(owning_agg, agg) { continue; }
            let bytes = &objects[oi as usize].sections[si as usize].bytes;
            let h = *blake3::hash(bytes).as_bytes();
            contributor_segs.push((SegmentRef::whole(oi, si), h));
        }
        if contributor_segs.is_empty() { continue; }
        contributor_segs.sort_by_key(|(seg, h)| (*h, seg.object, seg.section));

        let agg_nid = nodes.len() as NodeId;
        let segments: Vec<SegmentRef> = contributor_segs.iter().map(|(s, _)| *s).collect();
        for seg in &segments {
            node_of.insert((seg.object, seg.section), agg_nid);
        }
        // Bracket symbols enter as DefinedSymbols with no tu_id (not
        // from any TU). Per-segment defined symbols are appended in
        // the unified population pass below.
        let bracket_defs: Vec<DefinedSymbol> = agg.bracket_symbols
            .iter()
            .map(|name| DefinedSymbol {
                name: (*name).to_string(),
                bind: SymbolBind::Global,
                tu_id: None,
                value: 0,
            })
            .collect();
        nodes.push(NodeMeta {
            segments,
            aggregator_id: Some(agg.id),
            defined_symbols: bracket_defs,
        });
    }

    // Populate each node's `defined_symbols` from its segments.
    // Walking objects.symbols and dispatching via node_of routes
    // contributor-section symbols onto their aggregator node
    // automatically. For string-pool sections, dispatch by st_value:
    // each symbol attaches to the per-string node whose byte range
    // contains its address.
    for (oi, obj) in objects.iter().enumerate() {
        for sym in &obj.symbols {
            let Some(sec_idx) = sym.defining_section else { continue };
            if sym.name.is_empty() { continue; }
            let key = (oi as u32, sec_idx as u32);
            let nid_opt = if let Some(entries) = merge_pool_entries.get(&key) {
                find_pool_entry_node(entries, &string_node_of, key, sym.value as u32)
            } else {
                node_of.get(&key).copied()
            };
            let Some(nid) = nid_opt else { continue };
            nodes[nid as usize].defined_symbols.push(DefinedSymbol {
                name: sym.name.clone(),
                bind: sym.bind,
                tu_id: Some(obj.tu_id),
                value: sym.value,
            });
        }
    }

    // Per-node bytes hash, computed once for use as a content-stable
    // tiebreaker across scans whose object-iteration order differs.
    // Per-string nodes hash only their string's bytes (the segment's
    // range), so two scans whose string sits in different CGUs'
    // `.rodata.str1.1` produce the same fingerprint.
    let bytes_hash_of: Vec<[u8; 16]> = nodes
        .iter()
        .map(|nm| {
            let mut h = blake3::Hasher::new();
            for seg in &nm.segments {
                h.update(seg.bytes_in(&objects[seg.object as usize].sections));
            }
            let mut out = [0u8; 16];
            out.copy_from_slice(&h.finalize().as_bytes()[..16]);
            out
        })
        .collect();

    // Symbol index: map every defined symbol to its defining node.
    //
    // For multiply-defined globals (e.g. rust's per-crate `__rust_alloc`
    // shim that lives in many CGUs with byte-identical content), pick
    // the canonical NodeId by *content-derived tiebreaker* rather than
    // by scan iteration order. base and overlay scans of logically-
    // equivalent input sets can differ in object iteration order
    // (cargo regenerates rlibs whose internal member order varies on
    // each rebuild even when the encoded source set is the same), and
    // first-write-wins would then pick different canonicals between
    // scans. Different canonicals → different graph topology → SCC
    // structures that look isomorphic but route ~half the graph's
    // trans_hashes through subtly different node identities, blowing
    // up overlay closures with sections whose bytes match base
    // verbatim.
    //
    // Tiebreaker: lowest bytes_hash among all definers for the same
    // name. Identical content → identical bytes_hash → both scans
    // pick the same canonical. Bracket symbols (tu_id = None) are
    // synthesized — only one definer per name, so the tiebreaker is
    // a no-op for them.
    let mut symbols = SymbolIndex::default();
    for (nid, nm) in nodes.iter().enumerate() {
        let nid = nid as NodeId;
        for sym in &nm.defined_symbols {
            match sym.bind {
                SymbolBind::Global | SymbolBind::Weak => {
                    let new_h = bytes_hash_of[nid as usize];
                    match symbols.globals.entry(sym.name.clone()) {
                        std::collections::hash_map::Entry::Vacant(v) => {
                            v.insert((nid, sym.value));
                        }
                        std::collections::hash_map::Entry::Occupied(mut o) => {
                            let existing = o.get().0;
                            let existing_h = bytes_hash_of[existing as usize];
                            if new_h < existing_h {
                                o.insert((nid, sym.value));
                            }
                        }
                    }
                }
                SymbolBind::Local => {
                    let tu_id = sym.tu_id.expect("local symbol must carry tu_id");
                    symbols
                        .locals
                        .insert((sym.name.clone(), tu_id), (nid, sym.value));
                    symbols
                        .locals_any_tu
                        .entry(sym.name.clone())
                        .or_insert((nid, sym.value));
                }
            }
        }
    }

    // The trampoline target node (if the entry symbol resolves). Edges
    // into it are cut to external sentinels below.
    let entry_node = entry_symbol.and_then(|n| symbols.resolve_global(n)).map(|(n, _)| n);

    // Edges + external counts + per-reloc resolutions. Outgoing edges
    // come from each segment's relocs; aggregator nodes naturally
    // accumulate edges from all contributor segments because their
    // (obj, sec) → NodeId mappings all point at the aggregator. Every
    // reloc's resolution is also RECORDED (`reloc_targets`) so prune's
    // dispositions derive from the exact same answer the hash graph
    // used — resolve once, consume everywhere.
    let mut edges: Vec<Vec<NodeId>> = vec![Vec::new(); nodes.len()];
    let mut external_counts: Vec<u32> = vec![0; nodes.len()];
    let mut reloc_targets: HashMap<(u32, u32), HashMap<(u64, u32), ResolvedTarget>> =
        HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            let Some(&nid) = node_of.get(&(oi as u32, si as u32)) else {
                continue; // section was filtered (non-allocated)
            };
            let mut recorded: HashMap<(u64, u32), ResolvedTarget> = HashMap::new();
            for r in &sec.relocs {
                // Section-target relocs carry the physical target index
                // (`target_section`) — section names legally repeat
                // within one object, so resolution must NOT go through
                // names. Symbol targets go through the flat symbol
                // index (with `--wrap` renaming applied — ld redirects
                // the reference, so both the semantic dependency and
                // the resolution are on the wrapper). A target in a
                // filtered (non-alloc) section becomes an external
                // sentinel.
                let (resolved, edge_target) = if let Some(si0) = r.target_section {
                    let key = (oi as u32, si0);
                    // Edge precision: a string-pool ref depends on the
                    // specific string the addend lands in. The recorded
                    // Section target keeps the section's first node —
                    // the disposition path anchors at the section's
                    // recovered base with the addend riding along.
                    let edge = if let Some(entries) = merge_pool_entries.get(&key) {
                        find_pool_entry_node(entries, &string_node_of, key, r.addend as u32)
                    } else {
                        node_of.get(&key).copied()
                    };
                    match node_of.get(&key) {
                        Some(&sec_nid) => (ResolvedTarget::Section { nid: sec_nid }, edge),
                        None => (ResolvedTarget::External, None),
                    }
                } else if r.target.starts_with("<section:") {
                    // Section ref whose physical index parse() couldn't
                    // determine — nothing to resolve against.
                    (ResolvedTarget::External, None)
                } else {
                    let wrap_name;
                    let lookup: &str = if wrapped.contains(&r.target) {
                        wrap_name = format!("__wrap_{}", r.target);
                        &wrap_name
                    } else {
                        &r.target
                    };
                    match symbols.resolve(lookup, obj.tu_id) {
                        Some((t, value)) => (ResolvedTarget::Symbol { nid: t, value }, Some(t)),
                        None => (ResolvedTarget::External, None),
                    }
                };
                recorded.insert((r.offset, r.r_type), resolved);
                match edge_target {
                    Some(t) if t == nid => {
                        // self-edge — ignored for SCC; section already
                        // depends on itself trivially via its own bytes.
                    }
                    Some(t) if Some(t) == entry_node => {
                        // Trampoline cut: a reference to the entry target
                        // binds to its (trampolined) address, not its
                        // content. Fold in a sentinel so the entry's
                        // content doesn't propagate into this caller.
                        external_counts[nid as usize] += 1;
                    }
                    Some(t) => edges[nid as usize].push(t),
                    None => external_counts[nid as usize] += 1,
                }
            }
            if !recorded.is_empty() {
                reloc_targets.insert((oi as u32, si as u32), recorded);
            }
            // Dedup outgoing edges — multiple relocs to the same target
            // section shouldn't multiply-contribute to the hash input.
            edges[nid as usize].sort();
            edges[nid as usize].dedup();
        }
    }

    Graph {
        nodes,
        edges,
        external_edge_counts: external_counts,
        symbols,
        reloc_targets,
        entry_node,
    }
}

const SHF_MERGE: u64 = 0x10;
const SHF_STRINGS: u64 = 0x20;

/// Split a SHF_MERGE | SHF_STRINGS section's bytes into the
/// (offset, length) of each NUL-terminated string. Each entry includes
/// its trailing NUL byte (the linker dedupes on whole `<bytes>\0`
/// units). Assumes sh_entsize = 1, which is universal for rust-emitted
/// `.rodata.str1.1`.
fn split_nul_terminated(bytes: &[u8]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut start = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        if b == 0 {
            let end = i as u32 + 1;
            out.push((start, end - start));
            start = end;
        }
    }
    // Trailing bytes without a terminating NUL are anomalous; skip.
    out
}

/// Look up the per-entry LogicalNode whose byte range contains `addend`
/// within an (object, section) merge pool. `entries` is the list of
/// (offset, len) tuples — NUL-terminated strings or fixed-entsize cst
/// chunks — sorted by offset. Falls back to `None` if `addend` lies
/// past the last entry (shouldn't happen for well-formed input).
fn find_pool_entry_node(
    entries: &[(u32, u32)],
    string_node_of: &HashMap<(u32, u32, u32), NodeId>,
    key: (u32, u32),
    addend: u32,
) -> Option<NodeId> {
    // Entries are offset-ascending; binary-search by the largest
    // offset ≤ addend.
    let idx = entries.partition_point(|&(off, _)| off <= addend);
    if idx == 0 { return None; }
    let (off, len) = entries[idx - 1];
    if addend >= off + len { return None; }
    string_node_of.get(&(key.0, key.1, off)).copied()
}

/// Tarjan SCC. Returns `scc_of_node[n]` = scc id, `members[s]` = node
/// ids in scc `s`. SCC ids are assigned in *reverse topological order*:
/// `members[0]` has no outgoing edges to other SCCs, `members[last]` is
/// a root. This is exactly the order we need for computing transitive
/// hashes (successors first).
pub fn tarjan_scc(graph: &Graph) -> SccResult {
    let n = graph.edges.len();
    let mut index_counter: u32 = 0;
    let mut stack: Vec<NodeId> = Vec::new();
    let mut on_stack: Vec<bool> = vec![false; n];
    let mut index: Vec<Option<u32>> = vec![None; n];
    let mut lowlink: Vec<u32> = vec![0; n];
    let mut members: Vec<Vec<NodeId>> = Vec::new();
    let mut scc_of_node: Vec<u32> = vec![u32::MAX; n];

    // Iterative Tarjan to avoid stack overflow on large graphs. Each
    // "frame" tracks which child we've visited.
    enum Frame { Enter(NodeId), Return(NodeId, usize) }
    let mut call: Vec<Frame> = Vec::new();
    for start in 0..n as NodeId {
        if index[start as usize].is_some() { continue; }
        call.push(Frame::Enter(start));
        while let Some(frame) = call.pop() {
            match frame {
                Frame::Enter(v) => {
                    index[v as usize] = Some(index_counter);
                    lowlink[v as usize] = index_counter;
                    index_counter += 1;
                    stack.push(v);
                    on_stack[v as usize] = true;
                    call.push(Frame::Return(v, 0));
                }
                Frame::Return(v, child_i) => {
                    let edges = &graph.edges[v as usize];
                    if child_i < edges.len() {
                        let w = edges[child_i];
                        call.push(Frame::Return(v, child_i + 1));
                        if index[w as usize].is_none() {
                            call.push(Frame::Enter(w));
                        } else if on_stack[w as usize] {
                            let w_idx = index[w as usize].unwrap();
                            let lv = &mut lowlink[v as usize];
                            if w_idx < *lv { *lv = w_idx; }
                        }
                    } else {
                        // All children done — check if v is an SCC root.
                        if lowlink[v as usize] == index[v as usize].unwrap() {
                            let scc_id = members.len() as u32;
                            let mut scc: Vec<NodeId> = Vec::new();
                            loop {
                                let w = stack.pop().unwrap();
                                on_stack[w as usize] = false;
                                scc_of_node[w as usize] = scc_id;
                                scc.push(w);
                                if w == v { break; }
                            }
                            members.push(scc);
                        }
                        // Propagate lowlink up to caller (the Return frame
                        // above us) after the child's subtree is done.
                        let lv = lowlink[v as usize];
                        if let Some(Frame::Return(parent, _)) = call.last() {
                            let lp = &mut lowlink[*parent as usize];
                            if lv < *lp { *lp = lv; }
                        }
                    }
                }
            }
        }
    }

    SccResult { scc_of_node, members }
}

pub struct SccResult {
    pub scc_of_node: Vec<u32>,
    /// SCCs in reverse-topological order: `members[0]` is a leaf of the
    /// SCC DAG (successors are all in `members[<0]` = none). Iterate
    /// `0..members.len()` and successors are already computed.
    pub members: Vec<Vec<NodeId>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph_from(edges: Vec<Vec<NodeId>>) -> Graph {
        Graph {
            nodes: (0..edges.len() as u32)
                .map(|_| NodeMeta::segment(0, 0))
                .collect(),
            external_edge_counts: vec![0; edges.len()],
            edges,
            symbols: SymbolIndex::default(),
            reloc_targets: HashMap::new(),
            entry_node: None,
        }
    }

    #[test]
    fn scc_linear() {
        // 0 -> 1 -> 2, each its own SCC.
        let g = graph_from(vec![vec![1], vec![2], vec![]]);
        let r = tarjan_scc(&g);
        assert_eq!(r.members.len(), 3);
        // Reverse-topological order: the leaf (node 2) comes first.
        assert_eq!(r.members[0], vec![2]);
        assert_eq!(r.members[1], vec![1]);
        assert_eq!(r.members[2], vec![0]);
    }

    #[test]
    fn scc_cycle() {
        // 0 -> 1 -> 0, one SCC of two nodes.
        let g = graph_from(vec![vec![1], vec![0]]);
        let r = tarjan_scc(&g);
        assert_eq!(r.members.len(), 1);
        let mut s = r.members[0].clone();
        s.sort();
        assert_eq!(s, vec![0, 1]);
    }

    #[test]
    fn scc_self_loop_is_excluded_by_edge_builder() {
        // Confirms the edge builder would dedup self-loops (not tested
        // here — this is a pure-graph check).
        let g = graph_from(vec![vec![0]]);
        let r = tarjan_scc(&g);
        // A real self-edge forms an SCC of 1 (Tarjan handles it).
        assert_eq!(r.members.len(), 1);
    }

    #[test]
    fn scc_diamond() {
        // 0 -> 1 -> 3
        //  \-> 2 -/
        let g = graph_from(vec![vec![1, 2], vec![3], vec![3], vec![]]);
        let r = tarjan_scc(&g);
        assert_eq!(r.members.len(), 4);
        // Reverse topo: 3 first (leaf), then 1 and 2 (in some order), then 0.
        assert_eq!(r.members[0], vec![3]);
        assert!(r.members[3] == vec![0]);
    }
}
