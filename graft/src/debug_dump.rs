//! Diagnostic graph dump for cross-scan trans_hash divergence
//! analysis.
//!
//! Emits one line per scan node with everything needed to localize
//! where two scans of "logically equivalent" inputs disagree on
//! trans_hash propagation. Stable cross-scan keys (stripped object
//! path + section name) let an offline diff find which nodes diverge
//! and on which input.
//!
//! Wired into both `base::link` and `overlay::link` via the
//! `GRAFT_DEBUG_DUMP_GRAPH` env var; off by default.

use std::io::Write;
use std::path::Path;

use crate::scan::ScanResult;
use crate::graph;

/// Strip per-build hashes from rcgu filenames so that the resulting
/// path is stable across rebuilds of the same logical CGU. Cargo
/// emits `<crate>-<crate-hash>.<cgu-fp>.<build-fp>.rcgu.o` where
/// `<build-fp>` rerolls on every build; the rest is stable.
fn stripped_label(label: &str) -> String {
    if let Some(stem) = label.strip_suffix(".rcgu.o")
        && let Some(dot) = stem.rfind('.')
    {
        return format!("{}.rcgu.o", &stem[..dot]);
    }
    label.to_string()
}

/// Emit a TSV with one line per real (non-synthetic) graph node.
/// Columns:
///   `obj`              — stripped (build-hash-removed) object label
///   `tu_id`            — defining object's `blake3(stt_file)[:8]`
///   `sec`              — section name
///   `bytes_hash`       — first 8 bytes of `blake3(section bytes)`
///   `mih`              — first 8 bytes of `blake3(bytes ‖ canonical_relocs)`
///   `enc_relocs_hash`  — first 8 bytes of `blake3(canonical_relocs)`
///   `trans_hash`       — full 16-byte trans_hash, hex
///   `edges`            — count of internal out-edges
///   `external`         — count of out-of-scope (sentinel) edges
///   `scc_id`           — Tarjan-assigned SCC id (per-scan)
///   `scc_hash`         — full 16-byte trans_hash of the containing SCC
///   `edge_targets`     — comma-joined list of `<obj>|<sec>` keys for
///                        each outgoing edge target (intra-SCC marked
///                        with `=` prefix for the self-SCC marker, so
///                        you can see edges that resolve to "myself").
///   `succ_scc_hashes`  — comma-joined sorted list of distinct
///                        successor-SCC trans_hashes (the SAME values
///                        the SCC computation hashes in, in the SAME
///                        ORDER), so you can diff "what successors
///                        contributed to this node's trans_hash."
///   `nid`              — this node's per-scan node id. NOT stable
///                        across scans; exists because `obj|sec` keys
///                        are ambiguous (same-named sections, and
///                        string pools split into per-entry nodes that
///                        all share the input section's name).
///   `edge_nids`        — comma-joined dst node ids for each outgoing
///                        edge, same order as `edge_targets`. The only
///                        unambiguous way to follow edges offline.
///
/// All hashes are *prefixes* of the underlying blake3 output, sized
/// for diff readability while still producing collision-resistant
/// keys at the scales we care about.
pub fn dump_graph(path: &Path, scan: &ScanResult) -> std::io::Result<()> {
    let g = &scan.graph;
    let scc = graph::tarjan_scc(g);

    // Canonicalize reloc targets through the *exact* code path
    // `hash::compute` uses, so the dump faithfully reproduces the real
    // trans_hash inputs (a hand-rolled copy previously drifted — it
    // keyed on whole-section bytes and ignored string-pool sub-ranges,
    // reporting fingerprints `compute` never produced).
    let bytes_hashes = crate::hash::node_identity_hashes(g, &scan.objects);
    let resolver = crate::hash::ContentResolver::build(&scan.objects, g, &bytes_hashes);
    // Real per-node SCC hashes — this column used to just repeat
    // trans_hash, which misled the #42 dissection.
    let (_, scch_of_node) = crate::hash::compute_detailed(&scan.objects, g, &scc);

    // Per-node logical key (used for cross-scan join AND for emitting
    // edge target keys).
    let logical_key: Vec<String> = g
        .nodes
        .iter()
        .enumerate()
        .map(|(_nid, nm)| {
            // Aggregator nodes get a stable cross-scan key from their
            // aggregator_id (avoids depending on the contributor
            // segment list, which can be large). Ordinary nodes use
            // their segment list joined with `+`.
            if let Some(agg_id) = nm.aggregator_id {
                format!("aggregator\0{}", agg_id)
            } else {
                nm.segments
                    .iter()
                    .map(|seg| {
                        let label = stripped_label(&scan.inputs[seg.object as usize].label());
                        let sec = &scan.objects[seg.object as usize].sections[seg.section as usize];
                        format!("{}\0{}", label, sec.name)
                    })
                    .collect::<Vec<_>>()
                    .join("+")
            }
        })
        .collect();

    let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
    writeln!(
        f,
        "obj\ttu_id\tsec\tbytes_hash\tmih\tenc_relocs_hash\ttrans_hash\tedges\texternal\tscc_id\tscc_hash\tedge_targets\tsucc_scc_hashes\tnid\tedge_nids"
    )?;

    for (nid, nm) in g.nodes.iter().enumerate() {
        let th: String = scan.trans_hash[nid].iter().map(|b| format!("{b:02x}")).collect();
        let edges_count = g.edges[nid].len();
        let ext = g.external_edge_counts[nid];
        let sid = scc.scc_of_node[nid];

        // Edge targets as logical keys; mark intra-SCC with `=`.
        let edges_str: String = g.edges[nid]
            .iter()
            .map(|&dst| {
                let dst_sid = scc.scc_of_node[dst as usize];
                let prefix = if dst_sid == sid { "=" } else { "" };
                format!("{}{}", prefix, logical_key[dst as usize].replace('\0', "|"))
            })
            .collect::<Vec<_>>()
            .join(",");

        // Successor SCC scc_hashes — the EXACT inputs to this SCC's
        // trans_hash computation, re-derived for verification.
        let mut succ_scc_hashes: Vec<String> = Vec::new();
        let mut seen: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        for &member_nid in &scc.members[sid as usize] {
            for &dst in &g.edges[member_nid as usize] {
                let dst_sid = scc.scc_of_node[dst as usize];
                if dst_sid == sid { continue; }
                if seen.insert(dst_sid) {
                    let dst_th: String = scan.trans_hash[dst as usize]
                        .iter().map(|b| format!("{b:02x}")).collect();
                    succ_scc_hashes.push(dst_th);
                }
            }
        }
        succ_scc_hashes.sort();
        let succ_str = succ_scc_hashes.join(",");

        let edge_nids_str: String = g.edges[nid]
            .iter()
            .map(|&dst| dst.to_string())
            .collect::<Vec<_>>()
            .join(",");

        // One row per segment. nid/trans_hash/scc are node-level and
        // shared across segment rows; bytes/mih/enc_relocs are
        // per-segment so divergence localizes naturally.
        for seg in &nm.segments {
            let obj = &scan.objects[seg.object as usize];
            let sec = &obj.sections[seg.section as usize];

            // Bytes the way `hash::compute` sees them: per-string nodes
            // hash only their sub-range, not the whole pool section.
            let seg_bytes = seg.bytes_in(&obj.sections);

            let stripped = stripped_label(&scan.inputs[seg.object as usize].label());
            let tu_id_hex: String = obj.tu_id.iter().map(|b| format!("{b:02x}")).collect();
            let bh: String = blake3::hash(seg_bytes).as_bytes()[..8]
                .iter().map(|b| format!("{b:02x}")).collect();

            // Per-string segments (range = Some) contribute no relocs to
            // the member hash — string bytes reference nothing. Mirror
            // `hash::compute` exactly so this dump reproduces the real
            // trans_hash inputs.
            let canonical_relocs: Vec<u8> = if seg.range.is_some() {
                Vec::new()
            } else {
                let rebuilt: Vec<crate::elf::CanonicalReloc> = sec
                    .relocs
                    .iter()
                    .map(|r| {
                        let (target, addend) =
                            resolver.canonicalize_reloc(r, seg.object, obj.tu_id);
                        crate::elf::CanonicalReloc {
                            offset: r.offset,
                            target,
                            r_type: r.r_type,
                            addend,
                            target_section: None,
                        }
                    })
                    .collect();
                postcard::to_allocvec(&rebuilt).unwrap_or_default()
            };
            let enc_h: String = blake3::hash(&canonical_relocs).as_bytes()[..8]
                .iter().map(|b| format!("{b:02x}")).collect();

            let mut h = blake3::Hasher::new();
            h.update(seg_bytes);
            h.update(&canonical_relocs);
            let mih: String = h.finalize().as_bytes()[..8]
                .iter().map(|b| format!("{b:02x}")).collect();

            let scch: String =
                scch_of_node[nid].iter().map(|b| format!("{b:02x}")).collect();
            writeln!(
                f,
                "{stripped}\t{tu_id_hex}\t{}\t{bh}\t{mih}\t{enc_h}\t{th}\t{edges_count}\t{ext}\t{sid}\t{scch}\t{edges_str}\t{succ_str}\t{nid}\t{edge_nids_str}",
                sec.name,
            )?;
        }
    }

    Ok(())
}
