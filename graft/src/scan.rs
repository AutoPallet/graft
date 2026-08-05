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


/// Run the scan against eager paths (`.o`, `.rlib`) and deferred
/// archive paths (`.a`). `extra_roots` is a set of symbol names the
/// link argv asked for via `-u <sym>` / `--undefined=<sym>` — those
/// force-load their defining archive members regardless of whether
/// any other parsed object has an UND for them.
///
/// `wrapped` is the set of `--wrap=<sym>` names. ld redirects every
/// UND ref to `<sym>` into a UND ref to `__wrap_<sym>` for archive
/// demand-load purposes (and at relocation time). Mirroring that
/// here ensures the wrap function's defining `.o` gets pulled
/// (otherwise base.elf's `__wrap_<sym>` would be missing from our
/// scan/symhash machinery and prune would fail to resolve refs to
/// wrap targets).
pub fn run<P: AsRef<Path> + Sync>(
    eager_paths: &[P],
    deferred_paths: &[P],
    extra_roots: &[String],
    wrapped: &[String],
    // graft's single trampoline target. Edges into it are cut from the
    // trans_hash graph (see `graph::build`) so an edit to the entry
    // doesn't make its callers look changed. Base and overlay must pass
    // the same name for their trans_hashes to match.
    entry_symbol: Option<&str>,
) -> Result<ScanResult> {
    // Optional per-phase timing dump (`GRAFT_DEBUG=scan-timings`),
    // written to stderr. rustc swallows linker stderr on success, so
    // capture it via a direct `graft` invocation or `GRAFT_LOG`.
    let t0 = std::time::Instant::now();
    let mut marks: Vec<(&'static str, std::time::Duration)> = Vec::new();

    let collected = archive::collect_eager(eager_paths)?;
    let mut inputs = collected.inputs;
    let mut walked_archives = collected.walked_archives;
    marks.push(("collect_eager", t0.elapsed()));

    // Parse the eager objects — the scan's dominant cost at scale
    // (rust-analyzer: ~6.5k rlib members), and each parse is
    // independent: fan out across cores.
    use rayon::prelude::*;
    let mut objects: Vec<ParsedObject> = inputs
        .par_iter()
        .map(|inp| {
            elf::parse(&inp.bytes)
                .map_err(|e| anyhow::anyhow!("{}: {e}", inp.label()))
        })
        .collect::<Result<_>>()?;
    marks.push(("parse_eager", t0.elapsed()));

    // Open each deferred archive once. Read its symbol-index into
    // `symbol_index`: name → (archive_idx, member_offset). First
    // archive in input order wins on duplicate names.
    //
    // That is NOT always ld's answer. ld satisfies an undef from the
    // first archive at-or-after the position where the undef became
    // *live*: with archives A B C where only a member of B introduces
    // the undef, ld picks C's definition (even inside --start-group —
    // the same pass reaches C before any group restart revisits A),
    // while a global first-wins index picks A's. Hashing A's member
    // when base.elf contains C's makes later edits to C's copy
    // invisible — a silent stale bind. Until the scan models ld's
    // position semantics, `dup_defs` records every cross-archive
    // name collision, and demanding one whose candidate members'
    // bytes differ is a hard refusal (identical bytes → either pick
    // is interchangeable, proceed).
    let mut deferred: Vec<DeferredArchive> = Vec::with_capacity(deferred_paths.len());
    let mut symbol_index: HashMap<String, (usize, u64)> = HashMap::new();
    let mut dup_defs: HashMap<String, Vec<(usize, u64)>> = HashMap::new();
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
        //
        // A REPEATED listing (the esp-idf idiom: every component .a
        // appears several times in argv instead of --start-group) is
        // the same archive: index it once. ld rescans it at each
        // position, but against a global first-wins index the rescan
        // is a no-op — and counting one archive as several dup
        // candidates would poison the ambiguity guard below.
        if !walked_archives.insert(archive.canon_path.clone()) {
            continue;
        }
        let archive_idx = deferred.len();
        for (name, &offset) in &archive.symbol_to_offset {
            match symbol_index.entry(name.clone()) {
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert((archive_idx, offset));
                }
                std::collections::hash_map::Entry::Occupied(e) => {
                    let first = *e.get();
                    // Same-archive duplicates are fine: ld's archive-map
                    // walk and ours both take the first index entry.
                    if first.0 != archive_idx {
                        dup_defs
                            .entry(name.clone())
                            .or_insert_with(|| vec![first])
                            .push((archive_idx, offset));
                    }
                }
            }
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
    // Global definitions of the same name in scan.objects — which the
    // real linker rejects, and which would corrupt base address recovery.
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
    let wrap_set: HashSet<&str> = wrapped.iter().map(|s| s.as_str()).collect();
    let demand_name = |raw: &str| -> String {
        if wrap_set.contains(raw) {
            format!("__wrap_{raw}")
        } else {
            raw.to_string()
        }
    };
    // Refuse a demanded name that several deferred archives define with
    // DIFFERING member bytes — graft's position-independent pick could
    // diverge from ld's (see the dup_defs comment above). Byte-identical
    // candidates are interchangeable; let the first-wins pick stand.
    //
    // The refusal applies only to undefs INTRODUCED by a pulled archive
    // member (`from_member`): those become live mid-scan, and ld
    // satisfies them from the first archive at-or-after that position —
    // possibly not the globally-first definer. An undef live from
    // position zero — a `-u`/`--undefined` root, or a reference in an
    // eager input (rustc places every object/rlib before the library
    // archives on the link line) — is satisfied by the globally-first
    // definer in ld too, so first-wins is provably ld's pick there.
    // esp-idf leans on exactly this: it passes `-u __assert_func` so
    // ITS newlib override preempts toolchain libc.a's copy, which
    // duplicates the name with different bytes.
    // Weak-default preemption (the esp-idf pattern: esp_system defines
    // `esp_system_get_time_resolution` WEAK, esp_timer overrides it
    // STRONG): once both members are in the link, ELF binding picks
    // the strong def regardless of extraction order — not positional
    // at all. So a differing dup with exactly ONE strong candidate
    // proceeds, on the condition (checked after the demand fixpoint)
    // that the strong member actually got loaded; if nothing else
    // demands it, ld's binding can't be reproduced and we refuse.
    // Returns the strong candidate to defer-check, if any.
    let check_ambiguous = |name: &str, from_member: bool| -> Result<Option<(usize, u64)>> {
        if !from_member {
            return Ok(None);
        }
        let Some(cands) = dup_defs.get(name) else {
            return Ok(None);
        };
        // (ai, bytes, bind of the def) per candidate.
        let mut parsed: Vec<(usize, u64, Vec<u8>, Option<SymbolBind>)> = Vec::new();
        for &(ai, off) in cands {
            let inp = deferred[ai]
                .parse_member(off)
                .with_context(|| format!("parse member at {off:#x} in {}",
                    deferred[ai].path.display()))?;
            let obj = elf::parse(&inp.bytes)
                .map_err(|e| anyhow::anyhow!("{}: {e}", inp.label()))?;
            let bind = obj
                .symbols
                .iter()
                .find(|s| s.defining_section.is_some() && s.name == name)
                .map(|s| s.bind);
            parsed.push((ai, off, inp.bytes, bind));
        }
        // Byte-identical candidates are one candidate (two archives
        // shipping the same object): keep the first of each content.
        let mut distinct: Vec<&(usize, u64, Vec<u8>, Option<SymbolBind>)> = Vec::new();
        for c in &parsed {
            if !distinct.iter().any(|d| d.2 == c.2) {
                distinct.push(c);
            }
        }
        if let [_] = distinct.as_slice() {
            return Ok(None); // interchangeable
        }
        let strongs: Vec<&&(usize, u64, Vec<u8>, Option<SymbolBind>)> = distinct
            .iter()
            .filter(|(_, _, _, bind)| matches!(bind, Some(SymbolBind::Global)))
            .collect();
        if let [one] = strongs.as_slice() {
            return Ok(Some((one.0, one.1)));
        }
        bail!(
            "graft scan: symbol `{name}`, demanded by an archive member pulled \
             mid-scan, is defined by multiple deferred archives with differing \
             content and no unique strong definition ({}). graft's demand-load \
             picks the first archive in input order, but ld satisfies a \
             member-introduced undef from the first archive at-or-after the \
             point it became live — the picks can diverge, and hashing a member \
             base.elf doesn't contain makes later edits to the real one \
             invisible. Refusing (scan must mirror ld).",
            parsed
                .iter()
                .map(|(ai, _, _, _)| deferred[*ai].path.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        )
    };
    // (name, strong candidate) pairs from `check_ambiguous`, verified
    // loaded once the demand fixpoint completes.
    let mut strong_required: Vec<(String, (usize, u64))> = Vec::new();
    for sym_name in extra_roots {
        let lookup = demand_name(sym_name);
        if defined_globals.contains(&lookup) { continue; }
        if let Some(&(ai, off)) = symbol_index.get(&lookup)
            && loaded_members.insert((ai, off))
        {
            check_ambiguous(&lookup, false)?;
            pending.push((ai, off));
        }
    }
    let eager_count = objects.len();
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
                // Only a *strong* (STB_GLOBAL) undefined reference forces
                // an archive member to be extracted — this mirrors ld
                // exactly. A weak undef does NOT pull a member (ld leaves
                // it resolved to 0). Over-pulling on weak undefs would let
                // graft include + call code that base's real link left as
                // null, so base and overlay would disagree on whether the
                // symbol is a function or zero. `classify_bind` maps weak
                // undefs to `Weak` and strong undefs to `Global`, so this
                // filter is the precise ld-matching rule. (A genuinely
                // needed member is still pulled: any member with a strong
                // undef anywhere triggers the load.)
                if !matches!(sym.bind, SymbolBind::Global) {
                    continue;
                }
                if sym.name.is_empty() {
                    continue;
                }
                let lookup = demand_name(&sym.name);
                if defined_globals.contains(&lookup) {
                    continue;
                }
                if let Some(&(ai, off)) = symbol_index.get(&lookup)
                    && loaded_members.insert((ai, off))
                {
                    if let Some(strong) =
                        check_ambiguous(&lookup, next_obj_idx >= eager_count)?
                    {
                        strong_required.push((lookup.clone(), strong));
                    }
                    pending.push((ai, off));
                }
            }
            next_obj_idx += 1;
        }
    }

    // Deferred half of the weak-default dup rule: the unique strong
    // definition must actually be in the link, or the weak copy we
    // pulled is bound where ld would have bound the strong one.
    for (name, strong) in &strong_required {
        if !loaded_members.contains(strong) {
            bail!(
                "graft scan: symbol `{name}` has a weak default and a strong \
                 override in different deferred archives, and the strong \
                 member ({}) was never demand-loaded — ld's binding cannot be \
                 reproduced from graft's member set. Refusing (scan must \
                 mirror ld).",
                deferred[strong.0].path.display(),
            );
        }
    }

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
