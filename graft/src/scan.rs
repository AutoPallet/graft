//! One-shot scan: given a set of linker inputs, parse every reachable
//! object, build the forward-reloc graph, run Tarjan SCC, and compute
//! transitive hashes. Shared entry point for base and overlay modes.
//!
//! Eager inputs (loose `.o`s and `.rlib` archives) get parsed up front.
//! Deferred archives (`.a` system libraries, IDF components) are opened
//! for their symbol index only, then their `.o` members get demand-
//! parsed by a reachability loop seeded from the eagerly-loaded
//! objects' UND symbols + any `--undefined=foo` link-argv flags.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::archive::{self, DeferredArchive, ObjectInput};
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
    /// Canonical paths of `.a` / `.rlib` archives we expanded (any
    /// member parsed). Overlay uses this to know which forwarded
    /// `-l<name>` flags can be stripped from the link argv.
    pub walked_archives: HashSet<PathBuf>,
}

/// Run the scan against eager paths (`.o`, `.rlib`) and deferred
/// archive paths (`.a`). `extra_roots` is a set of symbol names the
/// link argv asked for via `-u <sym>` / `--undefined=<sym>` — those
/// force-load their defining archive members regardless of whether
/// any other parsed object has an UND for them.
pub fn run<P: AsRef<Path>>(
    eager_paths: &[P],
    deferred_paths: &[P],
    extra_roots: &[String],
) -> Result<ScanResult> {
    let collected = archive::collect_eager(eager_paths)?;
    let mut inputs = collected.inputs;
    let mut walked_archives = collected.walked_archives;

    // For each deferred archive, eagerly load every `.o` member.
    //
    // True lazy member discovery (only loading members the closure
    // actually reaches) is the eventual win — but it requires careful
    // attention to:
    //   - hash determinism: both base and overlay must reach the same
    //     loaded set so trans_hashes line up. A naive UND-driven walk
    //     diverges because graph.rs's last-write-wins symbol resolution
    //     depends on load order, and load order shifts with closure
    //     content.
    //   - linker-script demands: KEEP() patterns and CMakeLists-style
    //     `--whole-archive` brackets pin members irrespective of
    //     reachability from rust UNDs.
    // Until those land, we walk every member up-front. Performance
    // wise, archive walking is dominated by blake3 + SCC over the
    // resulting graph, not by archive-open cost; deferred-vs-eager
    // here is mostly an organizational distinction.
    let _ = extra_roots; // reserved for the future lazy discovery loop
    for p in deferred_paths {
        let p = p.as_ref();
        let Some(archive) = DeferredArchive::open(p)
            .with_context(|| format!("open deferred {}", p.display()))?
        else {
            continue; // stub linker script
        };
        // Walk every member's offset by iterating the archive itself.
        let archive_file = object::read::archive::ArchiveFile::parse(&*archive.bytes)
            .map_err(|e| anyhow::anyhow!("re-parse archive {}: {e}", archive.path.display()))?;
        for member in archive_file.members() {
            let member = member.map_err(|e| anyhow::anyhow!("archive member: {e}"))?;
            let name = String::from_utf8_lossy(member.name()).into_owned();
            if !(name.ends_with(".o") || name.ends_with(".rcgu.o")) {
                continue;
            }
            let data = member
                .data(&*archive.bytes)
                .map_err(|e| anyhow::anyhow!("member data: {e}"))?;
            inputs.push(crate::archive::ObjectInput {
                source_path: archive.path.clone(),
                member_name: Some(name),
                bytes: data.to_vec(),
            });
        }
        walked_archives.insert(archive.canon_path.clone());
    }

    // Parse every loaded object.
    let objects: Vec<ParsedObject> = inputs
        .iter()
        .map(|inp| {
            elf::parse(&inp.bytes)
                .map_err(|e| anyhow::anyhow!("{}: {e}", inp.label()))
        })
        .collect::<Result<_>>()?;

    let graph = graph::build(&objects);
    let scc = graph::tarjan_scc(&graph);
    let trans_hash = hash::compute(&objects, &graph, &scc);

    Ok(ScanResult {
        inputs,
        objects,
        graph,
        scc,
        trans_hash,
        walked_archives,
    })
}
