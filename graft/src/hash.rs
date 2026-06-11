//! Transitive hash computation.
//!
//! Processes SCCs in reverse topological order (successors first),
//! computes one transitive hash per SCC, then derives each node's
//! `trans_hash` by mixing the node's own member hash back in — so two
//! members of one cycle (e.g. xtensa code ↔ its literal pool) stay
//! distinguishable while still reflecting all transitive content.
//!
//! ```text
//! member_hash(n) = blake3(n.bytes || nominal_salt(n)?
//!                          || postcard(canonical_relocs(n)))
//! scc_hash(scc) = blake3(
//!     concat(sorted(member_hash(m) for m in scc))
//!     || concat(sorted(
//!         scc_hash(succ) for succ in distinct out-of-SCC successors
//!         ++ [[0u8;16] repeated external_edge_count times]
//!     ))
//! )[:16]
//! trans_hash(n) = blake3(scc_hash(scc_of(n)) || member_hash(n))[:16]
//! ```
//!
//! Members contribute a "bytes+relocs" hash so the SCC's final hash is
//! invariant under permutations of member order in the `.o` file.
//! Successor hashes are sorted so edge-order shifts (e.g. reloc
//! dedup / resort) don't affect the result.
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

use std::collections::{BTreeSet, HashMap};

use crate::graph::{Graph, SccResult};
use crate::elf::{CanonicalReloc, ParsedObject};

pub type TransHash = [u8; 16];

pub const EXTERNAL_SENTINEL: TransHash = [0u8; 16];

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
                h.update(seg.bytes_in(&objects[seg.object as usize].sections));
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
/// marker plus the section's sorted (stripped symbol name, st_value)
/// pairs — nominal identity for sections whose bytes don't define them.
/// Content-addressable sections have no entry (their hash input is
/// byte-for-byte what it was before this mechanism existed).
fn nominal_salts(objects: &[ParsedObject]) -> HashMap<(u32, u32), Vec<u8>> {
    let mut entries: HashMap<(u32, u32), Vec<(String, u64)>> = HashMap::new();
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
                v.push((strip_llvm_suffix(&sym.name).to_string(), sym.value));
            }
        }
    }
    entries
        .into_iter()
        .map(|(k, mut syms)| {
            syms.sort();
            syms.dedup();
            let mut blob = b"\0graft-nominal\0".to_vec();
            for (name, value) in &syms {
                blob.extend_from_slice(&(name.len() as u32).to_le_bytes());
                blob.extend_from_slice(name.as_bytes());
                blob.extend_from_slice(&value.to_le_bytes());
            }
            (k, blob)
        })
        .collect()
}

/// Strip rustc/LLVM's per-build internal-linkage suffix
/// (`foo.llvm.1234567890`) so the nominal salt doesn't churn when CGU
/// repartitioning renumbers it.
fn strip_llvm_suffix(name: &str) -> &str {
    match name.find(".llvm.") {
        Some(i) => &name[..i],
        None => name,
    }
}

/// Compute a `TransHash` for every node. All nodes in the same SCC
/// receive the same hash.
pub fn compute(
    objects: &[ParsedObject],
    graph: &Graph,
    scc: &SccResult,
) -> Vec<TransHash> {
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
                h.update(seg.bytes_in(&obj.sections));
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

    // Fan out: each node's trans_hash = SCC transitive hash ‖ its own
    // member-input hash. Members of a multi-node SCC share transitive
    // content but are DISTINCT sections that base places at distinct
    // addresses — on xtensa, code and its literal pool reference each
    // other (`.rwtext` ↔ `.rwtext.literal`) and so *always* form a
    // cycle. Folding an SCC onto one shared hash made `by_section[th]`
    // ill-defined: base's vote flagged the pair ambiguous and the
    // "representative" copy resolved `ram_resident_step` into the
    // middle of the literal pool. Mixing in the member hash keeps every
    // change-detection property (any transitive change still changes
    // the SCC hash, hence every member's value) while giving each
    // member a well-defined address mapping.
    graph.nodes.iter().enumerate().map(|(nid, _)| {
        let sid = scc.scc_of_node[nid];
        let mut h = blake3::Hasher::new();
        h.update(&scc_hash[sid as usize]);
        h.update(member_input_hash[nid].as_bytes());
        let mut out = [0u8; 16];
        out.copy_from_slice(&h.finalize().as_bytes()[..16]);
        out
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
        let _ = objects;
        let mut section = HashMap::new();
        let mut string_pool: HashMap<(u32, u32), Vec<(u32, u32, [u8; 8])>> = HashMap::new();
        let mut global = HashMap::new();
        let mut local = HashMap::new();
        for (nid, nm) in graph.nodes.iter().enumerate() {
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
            if r.addend >= 0
                && let Some(strings) = self.string_pool.get(&(obj_idx, si))
            {
                let a = r.addend as u32;
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
            if let Some(h) = self.section.get(&(obj_idx, si)) {
                return (format!("@{}", hex8(h)), r.addend);
            }
        }
        if let Some(h) = self.global.get(&r.target) {
            return (format!("@{}", hex8(h)), r.addend);
        }
        if let Some(h) = self.local.get(&(r.target.clone(), tu_id)) {
            return (format!("@{}", hex8(h)), r.addend);
        }
        // Out-of-scope target: keep the original name. The SCC
        // walker counts these as externals (sentinel hash), so the
        // name itself is never compared between scans.
        (r.target.clone(), r.addend)
    }
}

fn hex8(bytes: &[u8; 8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
