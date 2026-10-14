//! One-shot scan: given a set of linker inputs, parse every reachable
//! object, build the forward-reloc graph, run Tarjan SCC, and compute
//! transitive hashes. Shared entry point for base and overlay modes.
//!
//! Eager inputs (loose `.o`s and `.rlib` archives) get parsed up front.
//! Deferred archives (`.a` system libraries, IDF components) are opened
//! for their symbol index only, then their `.o` members get demand-
//! parsed at their command-line position, using strong undefined references
//! from preceding inputs and any `--undefined=foo` link-argv flags.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::archive::{self, DeferredArchive, ObjectInput};
use crate::elf::{self, ParsedObject, SymbolBind};
use crate::graph::{self, Graph, SccResult};
use crate::hash::{self, TransHash};

pub struct ScanResult {
    pub inputs: Vec<ObjectInput>,
    pub objects: Vec<ParsedObject>,
    pub graph: Graph,
    pub scc: SccResult,
    /// Indexed by `NodeId`. Per-node identity: the containing SCC's
    /// transitive hash mixed with the node's own member hash, so cycle
    /// members (xtensa code ↔ literal pool) don't collapse onto one
    /// value. See `hash::compute`.
    pub trans_hash: Vec<TransHash>,
    /// Canonical paths of `.a` / `.rlib` archives we expanded (any
    /// member parsed). Overlay uses this to know which forwarded
    /// `-l<name>` flags can be stripped from the link argv.
    pub walked_archives: HashSet<PathBuf>,
}

/// An ordered linker input. Groups rescan only their enclosed inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanInput {
    File(PathBuf),
    StartGroup,
    EndGroup,
}

/// Scan eager objects followed by archives, each searched once in the supplied
/// order. Use [`run_ordered`] for interleaved inputs or archive groups.
pub fn run<P: AsRef<Path> + Sync>(
    eager_paths: &[P],
    deferred_paths: &[P],
    extra_roots: &[String],
    wrapped: &[String],
    entry_symbol: Option<&str>,
) -> Result<ScanResult> {
    let inputs: Vec<_> = eager_paths
        .iter()
        .chain(deferred_paths)
        .map(|path| ScanInput::File(path.as_ref().to_path_buf()))
        .collect();
    run_ordered(&inputs, extra_roots, wrapped, entry_symbol)
}

/// Scan inputs in linker order. Loose objects and Rust rlibs are eager; native
/// archives extract members only for live strong undefined references. Repeated
/// archive entries rescan the same archive, and groups rescan until stable.
/// `extra_roots` supplies linker `-u` roots; `wrapped` supplies `--wrap` names.
/// `entry_symbol` cuts edges into Graft's trampoline target from transitive hashes.
pub fn run_ordered(
    ordered_inputs: &[ScanInput],
    extra_roots: &[String],
    wrapped: &[String],
    entry_symbol: Option<&str>,
) -> Result<ScanResult> {
    let t0 = std::time::Instant::now();
    let mut marks: Vec<(&'static str, std::time::Duration)> = Vec::new();
    let eager_paths: Vec<_> = ordered_inputs
        .iter()
        .filter_map(|input| match input {
            ScanInput::File(path) if path.extension().and_then(|s| s.to_str()) != Some("a") => {
                Some(path)
            }
            _ => None,
        })
        .collect();
    let collected = archive::collect_eager(&eager_paths)?;
    let mut inputs = collected.inputs;
    let mut walked_archives = collected.walked_archives;
    marks.push(("collect_eager", t0.elapsed()));

    use rayon::prelude::*;
    let mut objects: Vec<ParsedObject> = inputs
        .par_iter()
        .map(|inp| elf::parse(&inp.bytes).map_err(|e| anyhow::anyhow!("{}: {e}", inp.label())))
        .collect::<Result<_>>()?;
    marks.push(("parse_eager", t0.elapsed()));

    let mut eager_objects: HashMap<PathBuf, Vec<usize>> = HashMap::new();
    for (index, input) in inputs.iter().enumerate() {
        eager_objects
            .entry(input.source_path.clone())
            .or_default()
            .push(index);
    }
    let mut deferred = Vec::new();
    let mut archive_indices = HashMap::new();
    let mut plan = Vec::new();
    let mut group_stack = Vec::new();
    let mut group_ends = HashMap::new();
    for input in ordered_inputs {
        match input {
            ScanInput::File(path) if path.extension().and_then(|s| s.to_str()) == Some("a") => {
                let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                let index = if let Some(&index) = archive_indices.get(&canon) {
                    index
                } else {
                    let Some(archive) = DeferredArchive::open(path)
                        .with_context(|| format!("open deferred {}", path.display()))?
                    else {
                        continue;
                    };
                    let index = deferred.len();
                    walked_archives.insert(archive.canon_path.clone());
                    archive_indices.insert(canon, index);
                    deferred.push(archive);
                    index
                };
                plan.push(PlanEntry::Archive(index));
            }
            ScanInput::File(path) => {
                plan.push(PlanEntry::Eager(
                    eager_objects.remove(path).unwrap_or_default(),
                ));
            }
            ScanInput::StartGroup => {
                group_stack.push(plan.len());
                plan.push(PlanEntry::StartGroup);
            }
            ScanInput::EndGroup => {
                let start = group_stack
                    .pop()
                    .context("--end-group without --start-group")?;
                group_ends.insert(start, plan.len());
                plan.push(PlanEntry::EndGroup);
            }
        }
    }
    if !group_stack.is_empty() {
        bail!("--start-group without --end-group");
    }
    let mut state = LoadState {
        defined: HashSet::new(),
        undefined: HashSet::new(),
        wrapped: wrapped.iter().map(String::as_str).collect(),
        loaded_members: HashSet::new(),
        active_eager: HashSet::new(),
        generation: 0,
    };
    for root in extra_roots {
        state.undefined.insert(state.demand_name(root));
    }
    state.visit(
        &plan,
        &group_ends,
        0..plan.len(),
        &deferred,
        &mut inputs,
        &mut objects,
    )?;

    marks.push(("parse+demand", t0.elapsed()));
    let wrap_names: HashSet<String> = wrapped.iter().cloned().collect();
    let graph = graph::build(&objects, entry_symbol, &wrap_names);
    marks.push(("graph_build", t0.elapsed()));
    let scc = graph::tarjan_scc(&graph);
    marks.push(("tarjan", t0.elapsed()));
    let trans_hash = hash::compute(&objects, &graph, &scc);
    marks.push(("hash_compute", t0.elapsed()));
    if crate::debug_flags::enabled("scan-timings")? {
        let mut s = String::new();
        let mut prev = std::time::Duration::ZERO;
        for (name, at) in &marks {
            use std::fmt::Write as _;
            let _ = writeln!(s, "{name}: {:?} (cum {:?})", *at - prev, at);
            prev = *at;
        }
        eprint!("{s}");
    }

    Ok(ScanResult {
        inputs,
        objects,
        graph,
        scc,
        trans_hash,
        walked_archives,
    })
}

enum PlanEntry {
    Eager(Vec<usize>),
    Archive(usize),
    StartGroup,
    EndGroup,
}

struct LoadState<'a> {
    defined: HashSet<String>,
    undefined: HashSet<String>,
    wrapped: HashSet<&'a str>,
    loaded_members: HashSet<(usize, u64)>,
    active_eager: HashSet<usize>,
    generation: usize,
}

impl LoadState<'_> {
    fn demand_name(&self, name: &str) -> String {
        if self.wrapped.contains(name) {
            format!("__wrap_{name}")
        } else {
            name.to_owned()
        }
    }

    fn activate(&mut self, object: &ParsedObject) {
        for symbol in &object.symbols {
            if symbol.defining_section.is_some()
                && matches!(symbol.bind, SymbolBind::Global | SymbolBind::Weak)
                && !symbol.name.is_empty()
            {
                self.defined.insert(symbol.name.clone());
                self.undefined.remove(&symbol.name);
            }
        }
        for symbol in &object.symbols {
            // Weak undefined references do not extract archive members.
            if symbol.defining_section.is_none()
                && symbol.bind == SymbolBind::Global
                && !symbol.name.is_empty()
            {
                let name = self.demand_name(&symbol.name);
                if !self.defined.contains(&name) {
                    self.undefined.insert(name);
                }
            }
        }
        self.generation += 1;
    }

    fn archive(
        &mut self,
        index: usize,
        archive: &DeferredArchive,
        inputs: &mut Vec<ObjectInput>,
        objects: &mut Vec<ParsedObject>,
    ) -> Result<()> {
        loop {
            let before = self.generation;
            // Definitions and new demands take effect immediately, before the
            // next archive-index entry. Newly demanded earlier entries are
            // revisited on the next pass through this same archive.
            for (name, offset) in &archive.symbols {
                if !self.undefined.contains(name) || !self.loaded_members.insert((index, *offset)) {
                    continue;
                }
                let input = archive.parse_member(*offset).with_context(|| {
                    format!("parse member at {offset:#x} in {}", archive.path.display())
                })?;
                let object = elf::parse(&input.bytes)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", input.label()))?;
                self.activate(&object);
                inputs.push(input);
                objects.push(object);
            }
            if self.generation == before {
                return Ok(());
            }
        }
    }

    fn visit(
        &mut self,
        plan: &[PlanEntry],
        group_ends: &HashMap<usize, usize>,
        range: std::ops::Range<usize>,
        archives: &[DeferredArchive],
        inputs: &mut Vec<ObjectInput>,
        objects: &mut Vec<ParsedObject>,
    ) -> Result<()> {
        let mut position = range.start;
        while position < range.end {
            match &plan[position] {
                PlanEntry::Eager(indices) => {
                    for &index in indices {
                        if self.active_eager.insert(index) {
                            self.activate(&objects[index]);
                        }
                    }
                }
                PlanEntry::Archive(index) => {
                    self.archive(*index, &archives[*index], inputs, objects)?
                }
                PlanEntry::StartGroup => {
                    let group_end = group_ends[&position];
                    loop {
                        let before = self.generation;
                        self.visit(
                            plan,
                            group_ends,
                            position + 1..group_end,
                            archives,
                            inputs,
                            objects,
                        )?;
                        if self.generation == before {
                            break;
                        }
                    }
                    position = group_end;
                }
                PlanEntry::EndGroup => unreachable!("group delimiter consumed by recursive visit"),
            }
            position += 1;
        }
        Ok(())
    }
}
