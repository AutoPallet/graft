//! Transitive hash computation.
//!
//! Processes SCCs in reverse topological order (successors first) and
//! assigns one `trans_hash` per SCC. Every member section in the SCC
//! inherits that hash, so base and overlay builds can compare per-symbol
//! hashes via the flat `symbol → trans_hash` table.
//!
//! ```text
//! trans_hash(scc) = blake3(
//!     concat(sorted(
//!         blake3(member.bytes || postcard(canonical_relocs(member)))
//!         for member in scc
//!     ))
//!     || concat(sorted(
//!         trans_hash(succ) for succ in distinct out-of-SCC successors
//!         ++ [[0u8;16] repeated external_edge_count times]
//!     ))
//! )[:16]
//! ```
//!
//! Members contribute a "bytes+relocs" hash so the SCC's final hash is
//! invariant under permutations of member order in the `.o` file.
//! Successor hashes are sorted so edge-order shifts (e.g. reloc
//! dedup / resort) don't affect the result.

use std::collections::{BTreeSet, HashMap};

use crate::graph::{Graph, SccResult};
use crate::elf::{CanonicalReloc, ParsedObject};

pub type TransHash = [u8; 16];
pub type Symhash = [u8; 16];

pub const EXTERNAL_SENTINEL: TransHash = [0u8; 16];

/// Per-symbol fingerprint stored in `.graft.symhash`.
///
/// `symhash_of(stable_name, trans_hash) = blake3(stable_name? ‖ NUL ‖ trans_hash)`
///
/// `stable_name` is `Some(s)` for symbols whose name is invariant
/// across builds of the same source (most rust-mangled symbols, C
/// globals). It's `None` for symbols whose name embeds a
/// build-specific fingerprint that drifts on every cargo
/// incremental re-emit:
///   - `anon.<cgu_fp>.<n>(.llvm.<id>)?` — rustc anonymous data.
///   - Same shape used by some allocator/format internals.
///
/// Folding the stable name in disambiguates two distinct symbols that
/// happen to compile to byte-identical sections. Folding the
/// trans_hash in catches content + dependency changes — anon symbols
/// rely on this exclusively. Two builds of the same source produce
/// the same symhash regardless of CGU re-partitioning,
/// `.llvm.<digits>` suffix drift, or STT_SECTION ↔ symbol reloc form.
pub fn symhash_of(stable_name: Option<&str>, trans_hash: &TransHash) -> Symhash {
    let mut h = blake3::Hasher::new();
    if let Some(n) = stable_name {
        h.update(n.as_bytes());
    }
    h.update(b"\0");
    h.update(trans_hash);
    let digest = *h.finalize().as_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Extract the stable part of a symbol name, or `None` if the name is
/// build-noise. The classifier mirrors what `M1.q.2`'s
/// `ContentResolver::canonicalize_target` already strips for
/// trans_hash inputs:
///
///   - `anon.<hex>.<n>` (with optional `.llvm.<id>` suffix) → drop
///     entirely; identity is purely content-based.
///   - `<name>.llvm.<digits>` → strip the `.llvm.<digits>` suffix
///     (rustc internal-linkage symbols whose suffix shifts when CGU
///     content shifts). The pre-suffix part already includes rustc's
///     content-derived hash, so it's stable.
///   - Empty names → `None`.
///   - Otherwise → return as-is.
pub fn stable_name_part(name: &str) -> Option<&str> {
    if name.is_empty() {
        return None;
    }
    if name.starts_with("anon.") {
        return None;
    }
    // Strip a trailing `.llvm.<digits>` suffix if present.
    if let Some(idx) = name.rfind(".llvm.") {
        let suffix = &name[idx + ".llvm.".len()..];
        if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) {
            return Some(&name[..idx]);
        }
    }
    Some(name)
}

/// Per-node blake3 over the node's bytes — each segment respecting its
/// sub-range for per-string nodes, concatenated in segment order.
/// Aggregator nodes own their contributors as segments, so this
/// naturally captures the merged-output content. This is the content
/// fingerprint that both the trans_hash member-hash and the
/// `ContentResolver` canonicalization build on; exposed so the
/// diagnostic dump (`debug_dump`) can reproduce `compute` exactly
/// instead of re-deriving it (and drifting).
pub fn node_bytes_hashes(graph: &Graph, objects: &[ParsedObject]) -> Vec<blake3::Hash> {
    graph
        .nodes
        .iter()
        .map(|nm| {
            let mut h = blake3::Hasher::new();
            for seg in &nm.segments {
                h.update(seg.bytes_in(&objects[seg.object as usize].sections));
            }
            h.finalize()
        })
        .collect()
}

/// Compute a `TransHash` for every node. All nodes in the same SCC
/// receive the same hash.
pub fn compute(
    objects: &[ParsedObject],
    graph: &Graph,
    scc: &SccResult,
) -> Vec<TransHash> {
    // Two-pass member hashing. Pass 1: per-node blake3 of just the
    // section bytes — a stable content fingerprint that doesn't depend
    // on names, ordering, or other build-time noise. Pass 2: full
    // per-node hash (bytes + canonicalized reloc list, where reloc
    // target names are rewritten to content-fingerprints whenever the
    // name itself is build-time noise — see `canonicalize_target`).
    let bytes_hashes = node_bytes_hashes(graph, objects);
    let resolver = ContentResolver::build(objects, graph, &bytes_hashes);

    let member_input_hash: Vec<blake3::Hash> = graph
        .nodes
        .iter()
        .enumerate()
        .map(|(_nid, nm)| {
            let mut h = blake3::Hasher::new();
            for seg in &nm.segments {
                let obj = &objects[seg.object as usize];
                let sec = &obj.sections[seg.section as usize];
                h.update(seg.bytes_in(&obj.sections));
                // Per-string segments (range = Some) have no relocs
                // of their own — string bytes don't reference
                // anything. Skip the section's relocs so each string
                // node's input-hash is invariant to relocs that
                // belong to other parts of the section.
                if seg.range.is_none() {
                    let encoded = encode_relocs(&sec.relocs, seg.object, obj.tu_id, &resolver);
                    h.update(&encoded);
                }
            }
            h.finalize()
        })
        .collect();

    // Per-SCC trans_hash, in topological order (leaves first).
    let mut scc_hash: Vec<TransHash> = vec![[0u8; 16]; scc.members.len()];

    for (sid, members) in scc.members.iter().enumerate() {
        let mut h = blake3::Hasher::new();

        // Part 1: sorted member (bytes+relocs) hashes.
        let mut parts: Vec<[u8; 32]> = members
            .iter()
            .map(|&nid| *member_input_hash[nid as usize].as_bytes())
            .collect();
        parts.sort();
        for p in &parts { h.update(p); }

        // Part 2: sorted successor-SCC hashes, plus external sentinels.
        let self_sid = sid as u32;
        let mut succ_hashes: Vec<TransHash> = Vec::new();
        let mut seen_succ: BTreeSet<u32> = BTreeSet::new();
        let mut ext_count: u32 = 0;
        for &nid in members {
            for &dst in &graph.edges[nid as usize] {
                let dst_sid = scc.scc_of_node[dst as usize];
                if dst_sid == self_sid { continue; } // intra-SCC
                if seen_succ.insert(dst_sid) {
                    succ_hashes.push(scc_hash[dst_sid as usize]);
                }
            }
            ext_count += graph.external_edge_counts[nid as usize];
        }
        for _ in 0..ext_count { succ_hashes.push(EXTERNAL_SENTINEL); }
        succ_hashes.sort();
        for s in &succ_hashes { h.update(s); }

        let digest = *h.finalize().as_bytes();
        let mut trunc = [0u8; 16];
        trunc.copy_from_slice(&digest[..16]);
        scc_hash[sid] = trunc;
    }

    // Fan out SCC hashes to every node.
    graph.nodes.iter().enumerate().map(|(nid, _)| {
        let sid = scc.scc_of_node[nid];
        scc_hash[sid as usize]
    }).collect()
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
            let (target, addend) =
                resolver.canonicalize_target_with_addend(&r.target, r.addend, obj_idx, tu_id);
            CanonicalReloc { offset: r.offset, target, r_type: r.r_type, addend }
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
    /// (object_idx, section_name) → 8-byte content fingerprint.
    /// Used for `<section:NAME>` reloc-target resolution. Keyed
    /// per-object because multiple objects can have sections of the
    /// same name (e.g., every CGU emits `.text`). Pool sections (one
    /// physical section, many per-string LogicalNodes) are NOT in
    /// here — they live in `string_pool` instead.
    section: HashMap<(u32, String), [u8; 8]>,
    /// (object_idx, section_name) → sorted list of (offset, len,
    /// fingerprint) for SHF_MERGE | SHF_STRINGS sections. Used to
    /// canonicalize `<section:STR_POOL> + addend` refs to a specific
    /// string's fingerprint, so that anon refs to a particular
    /// string get a stable encoding regardless of which CGU's
    /// `.rodata.str1.1` happens to host the string in this build.
    string_pool: HashMap<(u32, String), Vec<(u32, u32, [u8; 8])>>,
    /// Global symbol name → defining-node content fingerprint.
    global: HashMap<String, [u8; 8]>,
    /// (local symbol name, defining tu_id) → defining-node content
    /// fingerprint. Locals can repeat by name across TUs; the tu_id
    /// disambiguates.
    local: HashMap<(String, [u8; 8]), [u8; 8]>,
}

impl ContentResolver {
    pub fn build(
        objects: &[ParsedObject],
        graph: &Graph,
        bytes_hashes: &[blake3::Hash],
    ) -> Self {
        use crate::elf::SymbolBind;
        let mut section = HashMap::new();
        let mut string_pool: HashMap<(u32, String), Vec<(u32, u32, [u8; 8])>> = HashMap::new();
        let mut global = HashMap::new();
        let mut local = HashMap::new();
        for (nid, nm) in graph.nodes.iter().enumerate() {
            let mut h = [0u8; 8];
            h.copy_from_slice(&bytes_hashes[nid].as_bytes()[..8]);
            for seg in &nm.segments {
                let sec_name = &objects[seg.object as usize].sections[seg.section as usize].name;
                match seg.range {
                    None => {
                        section.insert((seg.object, sec_name.clone()), h);
                    }
                    Some((off, len)) => {
                        string_pool
                            .entry((seg.object, sec_name.clone()))
                            .or_default()
                            .push((off, len, h));
                    }
                }
            }
            for sym in &nm.defined_symbols {
                match sym.bind {
                    SymbolBind::Global | SymbolBind::Weak => {
                        global.insert(sym.name.clone(), h);
                    }
                    SymbolBind::Local => {
                        let tu_id = sym.tu_id.expect("local symbol must carry tu_id");
                        local.insert((sym.name.clone(), tu_id), h);
                    }
                }
            }
        }
        for v in string_pool.values_mut() {
            v.sort_by_key(|&(off, _, _)| off);
        }
        Self { section, string_pool, global, local }
    }

    pub fn canonicalize_target_with_addend(
        &self,
        name: &str,
        addend: i64,
        obj_idx: u32,
        tu_id: [u8; 8],
    ) -> (String, i64) {
        // Section-targeted reloc. Try the per-string pool first
        // (pool and ordinary section maps are mutually exclusive for
        // any given (object, section_name)).
        if let Some(inner) = name.strip_prefix("<section:").and_then(|s| s.strip_suffix('>')) {
            if addend >= 0
                && let Some(strings) = self.string_pool.get(&(obj_idx, inner.to_string()))
            {
                let a = addend as u32;
                let idx = strings.partition_point(|&(off, _, _)| off <= a);
                if idx > 0 {
                    let (off, len, h) = strings[idx - 1];
                    if a < off + len {
                        return (format!("@{}", hex8(&h)), (a - off) as i64);
                    }
                }
                // Out-of-bounds addend in a string pool: fall through
                // to the section-level lookup (which won't have an
                // entry — pool and section are mutually exclusive),
                // then to the unmodified-name fallback.
            }
            if let Some(h) = self.section.get(&(obj_idx, inner.to_string())) {
                return (format!("@{}", hex8(h)), addend);
            }
        }
        if let Some(h) = self.global.get(name) {
            return (format!("@{}", hex8(h)), addend);
        }
        if let Some(h) = self.local.get(&(name.to_string(), tu_id)) {
            return (format!("@{}", hex8(h)), addend);
        }
        // Out-of-scope target: keep the original name. The SCC
        // walker counts these as externals (sentinel hash), so the
        // name itself is never compared between scans.
        (name.to_string(), addend)
    }
}

fn hex8(bytes: &[u8; 8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
