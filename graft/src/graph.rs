//! Cross-object forward-reloc graph + Tarjan SCC.
//!
//! Nodes = sections, numbered globally (flat index across all objects).
//! Edges = outgoing relocs, resolved through the symbol index. External
//! targets (not defined in our inputs) are *not* represented as nodes;
//! they're tracked per-section so the hash pass can fold them in as
//! sentinel hashes.

use std::collections::HashMap;

use crate::elf::{ParsedObject, SymbolBind};
use object::elf::SHF_ALLOC;

pub type NodeId = u32;

/// Identifies a symbol across all objects. Globals key on `name`; locals
/// on `(name, tu_id)` because the same mangled local-symbol name can
/// appear in multiple TUs.
#[derive(Debug, Default)]
pub struct SymbolIndex {
    globals: HashMap<String, NodeId>,
    locals: HashMap<(String, [u8; 8]), NodeId>,
}

impl SymbolIndex {
    pub fn resolve_global(&self, name: &str) -> Option<NodeId> {
        self.globals.get(name).copied()
    }
    pub fn resolve_local(&self, name: &str, tu_id: [u8; 8]) -> Option<NodeId> {
        self.locals.get(&(name.to_string(), tu_id)).copied()
    }
    pub fn globals_iter(&self) -> impl Iterator<Item = (&String, NodeId)> {
        self.globals.iter().map(|(n, &v)| (n, v))
    }
    pub fn locals_iter(&self) -> impl Iterator<Item = (&String, [u8; 8], NodeId)> {
        self.locals.iter().map(|((n, t), &v)| (n, *t, v))
    }
}

#[derive(Debug)]
pub struct Graph {
    /// One entry per node. Nodes are either real (one per allocated
    /// input section, in walk order) or synthetic (appended after the
    /// real ones, one per linker-aggregated output that scan-side
    /// inputs contribute to). Synthetic nodes have `object == u32::MAX`
    /// and corresponding metadata in `synthetic_meta`.
    pub nodes: Vec<NodeMeta>,
    /// `edges[n]` = list of internal destinations from node `n`.
    /// Real-node edges come from relocations; synthetic-node edges go
    /// to the contributing input sections.
    pub edges: Vec<Vec<NodeId>>,
    /// Count of external (unresolved-in-our-inputs) targets for each
    /// node. The hash pass folds these in as `[0u8; 16]` sentinels.
    pub external_edge_counts: Vec<u32>,
    pub symbols: SymbolIndex,
    /// Side table for synthetic nodes only. Indexed by NodeId; only
    /// populated for the synthetic suffix range. Carries the
    /// aggregator id and the synthetic+bracket symbol names defined
    /// on the phantom.
    pub synthetic: HashMap<NodeId, SyntheticInfo>,
}

#[derive(Debug, Clone)]
pub struct NodeMeta {
    /// `u32::MAX` for synthetic nodes (look up `synthetic[nid]`).
    pub object: u32,
    pub section: u32,
}

/// Metadata for a synthetic (linker-aggregated-output) graph node.
/// Successors (the contributing input sections) live in `Graph::edges`
/// the same as for real nodes.
#[derive(Debug, Clone)]
pub struct SyntheticInfo {
    /// Stable identifier from `synthetic::Aggregator::id`. Matches
    /// the merged-output section name in base.elf.
    pub aggregator_id: &'static str,
    /// Bracket symbols defined on this phantom (`__init_array_start`,
    /// `__init_array_end`, …). Their addresses live in base.elf's
    /// `.symtab`; refs from code resolve through the normal symhash
    /// machinery once these are registered in `Graph::symbols`.
    pub bracket_symbols: Vec<BracketSymbol>,
}

#[derive(Debug, Clone)]
pub struct BracketSymbol {
    pub name: String,
    pub end: BracketEnd,
}

#[derive(Debug, Clone, Copy)]
pub enum BracketEnd {
    /// Offset 0 within the merged output.
    Start,
    /// Offset = merged-output size.
    End,
}

/// Build the forward-reloc graph across a set of parsed objects.
pub fn build(objects: &[ParsedObject]) -> Graph {
    // Flat section index: (obj, sec) -> NodeId.
    let mut nodes: Vec<NodeMeta> = Vec::new();
    let mut node_of: HashMap<(u32, u32), NodeId> = HashMap::new();
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            // Skip non-allocated sections (`.note.GNU-stack`, `.comment`,
            // debug info, etc.) — they don't reach runtime, so they can't
            // be reached by the closure walk and shouldn't pollute it.
            // Anything with `SHF_ALLOC` clear lives only in the object
            // file; relocs targeting such a section (rare in practice)
            // resolve to nothing and end up as external sentinels.
            if sec.sh_flags & u64::from(SHF_ALLOC) == 0 {
                continue;
            }
            let nid = nodes.len() as NodeId;
            nodes.push(NodeMeta { object: oi as u32, section: si as u32 });
            node_of.insert((oi as u32, si as u32), nid);
        }
    }

    // Symbol index: map every defined symbol to its defining section's NodeId.
    let mut symbols = SymbolIndex::default();
    for (oi, obj) in objects.iter().enumerate() {
        for sym in &obj.symbols {
            let Some(sec_idx) = sym.defining_section else { continue };
            let Some(&nid) = node_of.get(&(oi as u32, sec_idx as u32)) else { continue };
            match sym.bind {
                SymbolBind::Global | SymbolBind::Weak => {
                    // First-write-wins on duplicate globals — mirrors
                    // ld's archive-resolution semantics (left-to-right
                    // argv search, first defining archive binds). Order-
                    // independent across base/overlay scans, which load
                    // archives in different sequences once lazy
                    // discovery lands.
                    symbols.globals.entry(sym.name.clone()).or_insert(nid);
                }
                SymbolBind::Local => {
                    symbols.locals.insert((sym.name.clone(), obj.tu_id), nid);
                }
            }
        }
    }

    // Synthesize phantom nodes for linker-aggregated outputs *before*
    // resolving reloc edges, so refs from code to bracket symbols
    // (`__init_array_start` etc.) land on the synthetic node instead
    // of becoming external sentinels.
    let mut synthetic: HashMap<NodeId, SyntheticInfo> = HashMap::new();
    let real_node_count = nodes.len();
    for agg in crate::synthetic::AGGREGATORS {
        let mut contributors: Vec<NodeId> = (0..real_node_count as NodeId)
            .filter(|&nid| {
                let nm = &nodes[nid as usize];
                let sec = &objects[nm.object as usize].sections[nm.section as usize];
                agg.contributor.matches(&sec.name)
            })
            .collect();
        if contributors.is_empty() { continue; }
        contributors.sort();
        contributors.dedup();

        let synth_nid = nodes.len() as NodeId;
        nodes.push(NodeMeta { object: u32::MAX, section: 0 });
        let bracket_symbols: Vec<BracketSymbol> = agg.bracket_symbols
            .iter()
            .map(|b| BracketSymbol {
                name: b.name.to_string(),
                end: match b.end {
                    crate::synthetic::BracketEnd::Start => BracketEnd::Start,
                    crate::synthetic::BracketEnd::End => BracketEnd::End,
                },
            })
            .collect();
        for b in &bracket_symbols {
            symbols.globals.entry(b.name.clone()).or_insert(synth_nid);
        }
        synthetic.insert(synth_nid, SyntheticInfo {
            aggregator_id: agg.id,
            bracket_symbols,
        });
    }

    // Per-object section-name → local section index. Used to resolve
    // `<section:...>` reloc targets (STT_SECTION / RelocationTarget::
    // Section) to the right NodeId within the same .o.
    let section_by_name_per_obj: Vec<HashMap<&str, u32>> = objects
        .iter()
        .map(|obj| {
            obj.sections
                .iter()
                .enumerate()
                .map(|(i, s)| (s.name.as_str(), i as u32))
                .collect()
        })
        .collect();

    // Edges + external counts. Allocated for every node (real +
    // synthetic). Synthetic-node edges to contributors are filled in
    // below; real-node edges come from reloc resolution.
    let mut edges: Vec<Vec<NodeId>> = vec![Vec::new(); nodes.len()];
    let mut external_counts: Vec<u32> = vec![0; nodes.len()];
    for (&synth_nid, _info) in &synthetic {
        // Recompute contributor list — same predicate as above. Cheap;
        // keeps this localized rather than threading a side channel.
        let agg = crate::synthetic::AGGREGATORS
            .iter()
            .find(|a| a.id == synthetic[&synth_nid].aggregator_id)
            .expect("synthetic node references unknown aggregator");
        let mut contribs: Vec<NodeId> = (0..real_node_count as NodeId)
            .filter(|&nid| {
                let nm = &nodes[nid as usize];
                let sec = &objects[nm.object as usize].sections[nm.section as usize];
                agg.contributor.matches(&sec.name)
            })
            .collect();
        contribs.sort();
        contribs.dedup();
        edges[synth_nid as usize] = contribs;
    }
    for (oi, obj) in objects.iter().enumerate() {
        for (si, sec) in obj.sections.iter().enumerate() {
            let Some(&nid) = node_of.get(&(oi as u32, si as u32)) else {
                continue; // section was filtered (non-allocated)
            };
            for r in &sec.relocs {
                // STT_SECTION / direct-section targets are encoded as
                // `<section:name>` by elf::parse. Resolve those within
                // the current object's sections; everything else goes
                // through the flat symbol index. A target that resolves
                // to a filtered section becomes an external sentinel.
                let target = if let Some(sec_name) = strip_section_marker(&r.target) {
                    section_by_name_per_obj[oi]
                        .get(sec_name)
                        .and_then(|&s_i| node_of.get(&(oi as u32, s_i)).copied())
                } else {
                    symbols
                        .resolve_global(&r.target)
                        .or_else(|| symbols.resolve_local(&r.target, obj.tu_id))
                };
                match target {
                    Some(t) if t != nid => edges[nid as usize].push(t),
                    Some(_) => {
                        // self-edge — ignored for SCC; section already
                        // depends on itself trivially via its own bytes.
                    }
                    None => external_counts[nid as usize] += 1,
                }
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
        synthetic,
    }
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

fn strip_section_marker(s: &str) -> Option<&str> {
    s.strip_prefix("<section:").and_then(|t| t.strip_suffix('>'))
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
            nodes: (0..edges.len() as u32).map(|_| NodeMeta { object: 0, section: 0 }).collect(),
            external_edge_counts: vec![0; edges.len()],
            edges,
            symbols: SymbolIndex::default(),
            synthetic: HashMap::new(),
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
