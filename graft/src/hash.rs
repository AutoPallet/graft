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

use std::collections::BTreeSet;

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
    // Per-member hash input: blake3(bytes || postcard(canonical_relocs)).
    let member_input_hash: Vec<blake3::Hash> = graph
        .nodes
        .iter()
        .map(|nm| {
            let sec = &objects[nm.object as usize].sections[nm.section as usize];
            let mut h = blake3::Hasher::new();
            h.update(&sec.bytes);
            let encoded = encode_relocs(&sec.relocs);
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

fn encode_relocs(relocs: &[CanonicalReloc]) -> Vec<u8> {
    // postcard gives us a stable, compact, order-preserving encoding of
    // the sorted reloc list. Relocs are pre-sorted by parse().
    postcard::to_allocvec(relocs).unwrap_or_default()
}
