//! One-shot scan: given a set of linker inputs, parse every reachable
//! object, build the forward-reloc graph, run Tarjan SCC, and compute
//! transitive hashes. Shared entry point for base and overlay modes.
//!
//! Eager inputs (loose `.o`s and `.rlib` archives) get parsed up front.
//! Deferred archives (`.a` system libraries, IDF components) are opened
//! for their symbol index only, then their `.o` members get demand-
//! parsed by a reachability loop seeded from the eagerly-loaded
//! objects' UND symbols + any `--undefined=foo` link-argv flags.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::archive::{self, DeferredArchive, ObjectInput};
use crate::elf::{self, ParsedObject, SymbolBind};
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

    // Parse the eager objects.
    let mut objects: Vec<ParsedObject> = inputs
        .iter()
        .map(|inp| {
            elf::parse(&inp.bytes)
                .map_err(|e| anyhow::anyhow!("{}: {e}", inp.label()))
        })
        .collect::<Result<_>>()?;

    // Open each deferred archive once. Read its symbol-index into
    // `symbol_index`: name → (archive_idx, member_offset). First
    // archive in input order wins on duplicate names — matches ld's
    // left-to-right archive search.
    let mut deferred: Vec<DeferredArchive> = Vec::with_capacity(deferred_paths.len());
    let mut symbol_index: HashMap<String, (usize, u64)> = HashMap::new();
    for p in deferred_paths {
        let p = p.as_ref();
        let Some(archive) = DeferredArchive::open(p)
            .with_context(|| format!("open deferred {}", p.display()))?
        else {
            continue; // stub linker script
        };
        // Mark walked at open time. Even if no member is demand-pulled,
        // the archive was processed by graft and the corresponding
        // `-l<name>` flag should be stripped from the link argv. ld
        // would otherwise re-pull the unfiltered original.
        walked_archives.insert(archive.canon_path.clone());
        let archive_idx = deferred.len();
        for (name, &offset) in &archive.symbol_to_offset {
            symbol_index
                .entry(name.clone())
                .or_insert((archive_idx, offset));
        }
        deferred.push(archive);
    }

    // Demand-load loop: any UND symbol in any loaded object that
    // resolves to a deferred-archive member AND isn't already defined
    // by a previously-loaded object triggers parsing of that member;
    // rinse and repeat. Mirrors ld's lazy archive resolution: ld
    // doesn't pull `libmain.a`'s app_main if Rust's eager
    // libesp_idf_sys.rlib already defines it. Without the
    // already-defined check, we'd over-pull and end up with multiple
    // Global definitions of the same name in scan.objects — which
    // base::build_symhash treats as a hard error per ld semantics.
    //
    // Seeded with `extra_roots` (`-u <sym>` / `--undefined=<sym>`)
    // so members ld would force-load via those flags also get pulled.
    let mut loaded_members: HashSet<(usize, u64)> = HashSet::new();
    let mut pending: Vec<(usize, u64)> = Vec::new();
    let mut defined_globals: HashSet<String> = HashSet::new();
    for obj in &objects {
        for sym in &obj.symbols {
            if sym.defining_section.is_none() { continue; }
            if !matches!(sym.bind, SymbolBind::Global | SymbolBind::Weak) { continue; }
            if sym.name.is_empty() { continue; }
            defined_globals.insert(sym.name.clone());
        }
    }
    for sym_name in extra_roots {
        if defined_globals.contains(sym_name) { continue; }
        if let Some(&(ai, off)) = symbol_index.get(sym_name)
            && loaded_members.insert((ai, off))
        {
            pending.push((ai, off));
        }
    }
    let mut next_obj_idx: usize = 0;
    while next_obj_idx < objects.len() || !pending.is_empty() {
        while let Some((ai, off)) = pending.pop() {
            let archive = &deferred[ai];
            let inp = archive
                .parse_member(off)
                .with_context(|| format!("parse member at {off:#x} in {}", archive.path.display()))?;
            let parsed = elf::parse(&inp.bytes)
                .map_err(|e| anyhow::anyhow!("{}: {e}", inp.label()))?;
            // Track this newly-loaded member's defined globals so
            // subsequent pulls don't re-pull the same name from a
            // different archive.
            for sym in &parsed.symbols {
                if sym.defining_section.is_none() { continue; }
                if !matches!(sym.bind, SymbolBind::Global | SymbolBind::Weak) { continue; }
                if sym.name.is_empty() { continue; }
                defined_globals.insert(sym.name.clone());
            }
            inputs.push(inp);
            objects.push(parsed);
        }
        while next_obj_idx < objects.len() {
            for sym in &objects[next_obj_idx].symbols {
                if sym.defining_section.is_some() {
                    continue;
                }
                if !matches!(sym.bind, SymbolBind::Global | SymbolBind::Weak) {
                    continue;
                }
                if sym.name.is_empty() {
                    continue;
                }
                if defined_globals.contains(&sym.name) {
                    continue;
                }
                if let Some(&(ai, off)) = symbol_index.get(&sym.name)
                    && loaded_members.insert((ai, off))
                {
                    pending.push((ai, off));
                }
            }
            next_obj_idx += 1;
        }
    }

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
