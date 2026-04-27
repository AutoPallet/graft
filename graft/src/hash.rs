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

pub const EXTERNAL_SENTINEL: TransHash = [0u8; 16];

/// Compute a `TransHash` for every node. All nodes in the same SCC
/// receive the same hash.
pub fn compute(
    objects: &[ParsedObject],
    graph: &Graph,
    scc: &SccResult,
) -> Vec<TransHash> {
    // Two-pass member hashing. Pass 1: per-section blake3 of just the
    // section bytes — used as a stable content fingerprint that
    // doesn't depend on names, ordering, or other build-time noise.
    // Pass 2: full per-section hash (bytes + canonicalized reloc list,
    // where reloc target names are rewritten to content-fingerprints
    // whenever the name itself is build-time noise — see
    // `canonicalize_target`).
    let bytes_hashes: Vec<blake3::Hash> = graph
        .nodes
        .iter()
        .map(|nm| {
            blake3::hash(&objects[nm.object as usize].sections[nm.section as usize].bytes)
        })
        .collect();
    let resolver = ContentResolver::build(objects, graph, &bytes_hashes);

    let member_input_hash: Vec<blake3::Hash> = graph
        .nodes
        .iter()
        .map(|nm| {
            let obj = &objects[nm.object as usize];
            let sec = &obj.sections[nm.section as usize];
            let mut h = blake3::Hasher::new();
            h.update(&sec.bytes);
            let encoded = encode_relocs(&sec.relocs, nm.object, obj.tu_id, &resolver);
            h.update(&encoded);
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
        .map(|r| CanonicalReloc {
            offset: r.offset,
            target: resolver.canonicalize_target(&r.target, obj_idx, tu_id),
            r_type: r.r_type,
            addend: r.addend,
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
struct ContentResolver {
    /// (object_idx, section_name) → 8-byte content fingerprint.
    /// Used for `<section:NAME>` reloc-target resolution. Keyed
    /// per-object because multiple objects can have sections of the
    /// same name (e.g., every CGU emits `.text`).
    section: HashMap<(u32, String), [u8; 8]>,
    /// Global symbol name → defining-section content fingerprint.
    /// Same name across objects collapses to one entry — globals are
    /// (by definition) unique by name, so identical content is
    /// expected.
    global: HashMap<String, [u8; 8]>,
    /// (local symbol name, defining tu_id) → defining-section
    /// content fingerprint. Locals can repeat by name across TUs;
    /// the tu_id disambiguates.
    local: HashMap<(String, [u8; 8]), [u8; 8]>,
}

impl ContentResolver {
    fn build(
        objects: &[ParsedObject],
        graph: &Graph,
        bytes_hashes: &[blake3::Hash],
    ) -> Self {
        use crate::elf::SymbolBind;
        let mut section = HashMap::new();
        let mut global = HashMap::new();
        let mut local = HashMap::new();
        for (nid, nm) in graph.nodes.iter().enumerate() {
            let mut h = [0u8; 8];
            h.copy_from_slice(&bytes_hashes[nid].as_bytes()[..8]);
            let obj = &objects[nm.object as usize];
            let sec = &obj.sections[nm.section as usize];
            section.insert((nm.object, sec.name.clone()), h);
            for &sym_idx in &sec.defined_symbols {
                let sym = &obj.symbols[sym_idx];
                if sym.name.is_empty() {
                    continue;
                }
                match sym.bind {
                    SymbolBind::Global | SymbolBind::Weak => {
                        global.insert(sym.name.clone(), h);
                    }
                    SymbolBind::Local => {
                        local.insert((sym.name.clone(), obj.tu_id), h);
                    }
                }
            }
        }
        Self { section, global, local }
    }

    fn canonicalize_target(&self, name: &str, obj_idx: u32, tu_id: [u8; 8]) -> String {
        // Section-targeted reloc.
        if let Some(inner) = name.strip_prefix("<section:").and_then(|s| s.strip_suffix('>'))
            && let Some(h) = self.section.get(&(obj_idx, inner.to_string()))
        {
            return format!("@{}", hex8(h));
        }
        // Global symbol reloc. Look up by full name (with whatever
        // `.llvm.<id>` suffix it carries — both base and overlay see
        // the same suffix when the target is in-scope, since the
        // suffix comes from the target's own CGU). Falls through if
        // the symbol isn't in our inputs (e.g., resolved later via
        // `-l<lib>` static archive that scan doesn't see, or libc).
        if let Some(h) = self.global.get(name) {
            return format!("@{}", hex8(h));
        }
        // Local symbol reloc.
        if let Some(h) = self.local.get(&(name.to_string(), tu_id)) {
            return format!("@{}", hex8(h));
        }
        // Out-of-scope target: keep the original name. The SCC
        // walker counts these as externals (sentinel hash), so the
        // name itself is never compared between scans.
        name.to_string()
    }
}

fn hex8(bytes: &[u8; 8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
