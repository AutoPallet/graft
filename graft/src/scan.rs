//! One-shot scan: given a set of linker inputs, parse every object,
//! build the forward-reloc graph, run Tarjan SCC, and compute
//! transitive hashes. This is the shared entry point base and overlay
//! modes both call.

use std::path::Path;

use anyhow::Result;

use crate::archive::{self, ObjectInput};
use crate::elf::{self, ParsedObject};
use crate::graph::{self, Graph, SccResult};
use crate::hash::{self, TransHash};

pub struct ScanResult {
    pub inputs: Vec<ObjectInput>,
    pub objects: Vec<ParsedObject>,
    pub graph: Graph,
    pub scc: SccResult,
    /// Indexed by `NodeId`. All members of an SCC share a hash.
    pub trans_hash: Vec<TransHash>,
}

pub fn run<P: AsRef<Path>>(paths: &[P]) -> Result<ScanResult> {
    let inputs = archive::collect_objects(paths)?;
    let objects: Vec<ParsedObject> = inputs
        .iter()
        .map(|inp| elf::parse(&inp.bytes).map_err(|e| anyhow::anyhow!("{}: {e}", inp.label())))
        .collect::<Result<_>>()?;

    let graph = graph::build(&objects);
    let scc = graph::tarjan_scc(&graph);
    let trans_hash = hash::compute(&objects, &graph, &scc);

    Ok(ScanResult { inputs, objects, graph, scc, trans_hash })
}
