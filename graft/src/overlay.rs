//! Overlay mode: re-link, pruned against a prior base build.
//!
//! Pipeline (per doc 06 § "Overlay mode"):
//!   1. Parse argv                       (argv::parse)
//!   2. Load base metadata               (from `GRAFT_BASE_ELF`)
//!   3. Hash + graph overlay's inputs    (scan::run)
//!   4. Compute closure                  (reachability walk from `main`,
//!                                        with per-section trans_hash
//!                                        match against base.symhash)
//!   5. Prune each input `.o`            (separate `prune` module)
//!   6. Generate base_symbols.ld         (PROVIDE entries for hits)
//!   7. Exec real linker                 (with pruned .o's + scripts)
//!   8. Package                          (M0.5: just write overlay.elf)
//!
//! Steps 1–4 + 6 live here; pruning lives in `prune.rs`; step 7 shells
//! out to the real `ld` via `$GRAFT_REAL_LD`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, anyhow, bail};

use crate::argv;
use crate::elf::SymbolBind;
use crate::elf_attach;
use crate::graph::NodeId;
use crate::hash::TransHash;
use crate::metadata::{
    self, GraftManifest, SCHEMA_VERSION, SECTION_MANIFEST, SECTION_SYMHASH, SymHashEntry,
};
use crate::prune;
use crate::roots;
use crate::scan::{self, ScanResult};

pub fn link(argv: Vec<String>) -> ExitCode {
    match run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft overlay: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(argv: Vec<String>) -> Result<()> {
    let t_start = std::time::Instant::now();

    // Mirror base mode's `--ldproxy-cwd` handling so relative archive
    // paths from esp-idf-sys (e.g. `esp-idf/xtensa/libxtensa.a`)
    // resolve the same way base saw them.
    if let Some(cwd) = crate::base::extract_flag(&argv, "--ldproxy-cwd") {
        std::env::set_current_dir(&cwd)
            .with_context(|| format!("chdir to --ldproxy-cwd {cwd}"))?;
    }

    let link_args = argv::parse(&argv);
    let output = link_args
        .output
        .clone()
        .ok_or_else(|| anyhow!("no -o <path> in argv"))?;

    let base_path: PathBuf = std::env::var("GRAFT_BASE_ELF")
        .map(PathBuf::from)
        .map_err(|_| anyhow!("GRAFT_BASE_ELF not set"))?;
    let base = load_base_metadata(&base_path)?;

    let driver = crate::argv::driver_path(&argv);
    let (eager_inputs, deferred_inputs) = resolve_scan_inputs(&link_args, &driver);
    let t_scan_start = std::time::Instant::now();
    let scan = scan::run(&eager_inputs, &deferred_inputs, &link_args.undefined, &link_args.wrapped)
        .context("overlay pre-scan")?;
    let t_scan = t_scan_start.elapsed();

    if let Ok(p) = std::env::var("GRAFT_DEBUG_DUMP_GRAPH")
        && !p.is_empty()
    {
        if let Err(e) = crate::debug_dump::dump_graph(std::path::Path::new(&p), &scan) {
            eprintln!("graft overlay: GRAFT_DEBUG_DUMP_GRAPH write {p} failed: {e}");
        }
    }

    let t_closure_start = std::time::Instant::now();
    let roots = roots::find_roots(&scan, &base, &link_args)?;
    let closure = compute_closure(&scan, &base, &roots)?;
    let t_closure = t_closure_start.elapsed();

    // Scratch dir next to the output path. Cleaned and recreated each
    // run so stale pruned .o's from a prior invocation don't confuse
    // the real linker.
    let work_dir = work_dir_for(&output);
    if work_dir.exists() {
        let _ = std::fs::remove_dir_all(&work_dir);
    }
    std::fs::create_dir_all(&work_dir)
        .with_context(|| format!("create {}", work_dir.display()))?;

    // Build the symhash-keyed resolver inputs.
    //
    // `overlay_symhash_by_name`: for every defined symbol in any
    // section graft scanned, compute its overlay-side symhash from
    // (stable_name_part, section's trans_hash). Prune uses this to
    // translate reloc target names (which it sees in raw `.o` symtabs)
    // into content-keyed lookups against base's `by_symhash`.
    //
    // `closure_symhashes`: the symhashes of every symbol defined in a
    // closure-included section. Cross-`.o` relocs targeting these
    // must NOT be SHN_ABS-rewritten to base (their content differs);
    // ld must resolve them to overlay's own re-emitted copy.
    //
    // `base_addr_by_name`: name → address from base.elf's `.symtab`.
    // Only consulted for the `__wrap_<sym>` lookup path — wrap names
    // are stable, no symhash dance needed.
    let mut overlay_symhash_by_name: HashMap<(String, [u8; 8]), crate::hash::Symhash> =
        HashMap::new();
    let mut overlay_symhash_globals: HashMap<String, crate::hash::Symhash> = HashMap::new();
    // Fallback for cross-CGU references where the source `.o`'s tu_id
    // doesn't match the target's defining `.o`. First-write-wins per
    // name; safe because two locals with the same stable_name and
    // identical content also share a symhash by construction.
    let mut overlay_symhash_locals_any_tu: HashMap<String, crate::hash::Symhash> = HashMap::new();
    for (oi, obj) in scan.objects.iter().enumerate() {
        for sym in &obj.symbols {
            if sym.name.is_empty() {
                continue;
            }
            let Some(sec_idx) = sym.defining_section else { continue };
            let nid_opt = crate::base::node_id_of(&scan.graph, oi as u32, sec_idx as u32);
            let Some(nid) = nid_opt else { continue };
            let th = scan.trans_hash[nid as usize];
            let sh = crate::hash::symhash_of(crate::hash::stable_name_part(&sym.name), &th);
            match sym.bind {
                SymbolBind::Global | SymbolBind::Weak => {
                    overlay_symhash_globals.entry(sym.name.clone()).or_insert(sh);
                }
                SymbolBind::Local => {
                    overlay_symhash_by_name.insert((sym.name.clone(), obj.tu_id), sh);
                    overlay_symhash_locals_any_tu
                        .entry(sym.name.clone())
                        .or_insert(sh);
                }
            }
        }
    }
    // Aggregator-node bracket symbols are global definitions too —
    // include them in `overlay_symhash_globals` so refs to
    // `__init_array_start` / etc. flow through the same
    // symhash-routed lookup as any other base-defined name.
    for (nid, nm) in scan.graph.nodes.iter().enumerate() {
        let th = scan.trans_hash[nid];
        for sym in &nm.defined_symbols {
            if sym.tu_id.is_some() { continue; } // not a bracket
            let sh = crate::hash::symhash_of(crate::hash::stable_name_part(&sym.name), &th);
            overlay_symhash_globals.entry(sym.name.clone()).or_insert(sh);
        }
    }
    let closure_symhashes: HashSet<crate::hash::Symhash> = {
        let mut s = HashSet::new();
        for &nid in &closure.closure {
            let nm = &scan.graph.nodes[nid as usize];
            let th = scan.trans_hash[nid as usize];
            for sym in &nm.defined_symbols {
                let sh = crate::hash::symhash_of(crate::hash::stable_name_part(&sym.name), &th);
                s.insert(sh);
            }
        }
        s
    };
    let base_resolver_wrapped: HashSet<String> =
        link_args.wrapped.iter().cloned().collect();
    let base_resolver = prune::BaseResolver {
        by_symhash: &base.by_symhash,
        base_symtab: &base.by_name,
        wrapped: &base_resolver_wrapped,
        closure_symhashes: &closure_symhashes,
        overlay_symhash_globals: &overlay_symhash_globals,
        overlay_symhash_locals: &overlay_symhash_by_name,
        overlay_symhash_locals_any_tu: &overlay_symhash_locals_any_tu,
    };

    // Prune each source object; collect the pruned-.o paths.
    let t_prune_start = std::time::Instant::now();
    let pruned = prune_all(&scan, &closure, &base_resolver, &work_dir)?;
    let t_prune = t_prune_start.elapsed();
    let abs_rewrites_total: usize = pruned.iter().map(|p| p.abs_rewrites).sum();
    let kept_sec_total: usize = pruned.iter().map(|p| p.kept_sections).sum();

    // Compute the set of `-l<name>` flags the link argv should drop:
    // every name whose resolved archive path was actually walked by
    // scan. Walked archives are now in `pruned` as filtered `.a`s; if
    // we left the original `-l<name>` in, ld would pull the unfiltered
    // version alongside, causing duplicate symbols.
    let stripped_libs: HashSet<String> = link_args
        .libs
        .iter()
        .filter_map(|name| {
            let path = crate::argv::resolve_lib(name, &link_args.library_paths)
                .or_else(|| crate::argv::resolve_lib_via_driver(name, &driver))?;
            let canon = std::fs::canonicalize(&path).unwrap_or(path);
            scan.walked_archives.contains(&canon).then(|| name.clone())
        })
        .collect();

    // Overlay is a **full** static link — every symbol it references is
    // either defined in the closure's own pruned .o's or PROVIDEd at a
    // constant base-derived address by `base_symbols.ld`. Combine just
    // splices the resulting sections into base; no relocation work at
    // combine time.
    //
    // Full-linking requires that base is a non-PIE static ELF so every
    // symbol has a permanent absolute address we can PROVIDE. (The
    // fixture's cargo config wires this up via the musl target +
    // `relocation-model=static`.)
    // Two layout strategies depending on target:
    //
    // - x86_64 hosted (e2e/x86 fixture): single SECTIONS block in
    //   `overlay_layout.ld` placing every alloc'd section at a
    //   contiguous bump-allocated range starting at OVERLAY_BASE_ADDR.
    //
    // - xtensa (esp32s3): pass through esp-hal's linker scripts almost
    //   verbatim; only mutate `memory.x`'s `irom_seg` / `drom_seg`
    //   ORIGIN/len so overlay code/data lands in the slack past base's
    //   used flash. Everything else (alias.x, esp32s3.x, hal-defaults.x,
    //   the per-section INSERT BEFORE machinery) keeps working as-is.
    let base_bytes_for_layout =
        std::fs::read(&base_path).with_context(|| format!("read {}", base_path.display()))?;
    let e_machine = base_e_machine(&base_bytes_for_layout)?;
    let mode = crate::slack::Mode::resolve(e_machine)?;
    if mode == crate::slack::Mode::Append && e_machine == object::elf::EM_XTENSA {
        bail!(
            "GRAFT_OVERLAY_MODE=append is unsupported on xtensa: the ESP-IDF bootloader \
             maps only one IROM/DROM segment per image. Use splice mode."
        );
    }

    let xtensa_layout = if e_machine == object::elf::EM_XTENSA {
        Some(setup_xtensa_layout(&work_dir, &base_bytes_for_layout, &argv)?)
    } else {
        None
    };
    // overlay_layout.ld is always passed to ld (run_real_linker
    // unconditionally adds `-T overlay_layout.ld`). The contents differ
    // by (mode, target):
    //   - xtensa: empty stub; layout comes from linkall.x + memory.x.
    //   - x86 splice: SECTIONS placing .text/.rodata at slack vaddrs.
    //   - x86 append: SECTIONS placing all alloc'd at OVERLAY_BASE_ADDR.
    let layout_script = work_dir.join("overlay_layout.ld");
    if xtensa_layout.is_some() {
        std::fs::write(&layout_script, b"/* xtensa: linkall.x carries the layout. */\n")
            .with_context(|| format!("write {}", layout_script.display()))?;
    } else if mode == crate::slack::Mode::Splice {
        let slack = compute_slack(&base_bytes_for_layout)?;
        write_overlay_layout_ld_splice(&layout_script, &slack)?;
    } else {
        let overlay_base_addr = compute_overlay_base_addr(&base_path)?;
        write_overlay_layout_ld(&layout_script, overlay_base_addr)?;
    }

    let overlay_elf = work_dir.join("overlay.elf");
    let t_link_start = std::time::Instant::now();
    // Aggregate verify list across pruned objects. Channel-2 hits
    // skip verify via verify_name=None at emit time; channel-3 hits
    // arrive here. Same name should resolve to the same vaddr in
    // every prune (resolution is deterministic per overlay run);
    // collapse duplicates and bail if any disagree.
    //
    // Aggregator brackets (`__init_array_start/end` etc.) deliberately
    // aren't exempted: their values are layout-derived in overlay's
    // link the same way `_bss_start/end` is, and silently accepting
    // base's address would mask the failure mode where a new/removed
    // constructor changes the aggregator's content but graft can't
    // detect it (scan doesn't see archive-member contributors that
    // ld pulls via `KEEP(*(.init_array .init_array.*))`). Letting
    // verify fail loud is the only signal we have. See
    // docs/13-early-trampoline.md.
    let mut assumed_names: HashMap<String, u64> = HashMap::new();
    for p in &pruned {
        for (name, addr) in &p.assumed_names {
            match assumed_names.entry(name.clone()) {
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(*addr);
                }
                std::collections::hash_map::Entry::Occupied(o) => {
                    if *o.get() != *addr {
                        bail!(
                            "graft prune: {name} resolved to two distinct addresses \
                             ({:#x} and {addr:#x}) across pruned `.o`s",
                            o.get(),
                        );
                    }
                }
            }
        }
    }
    if pruned.is_empty() {
        write_empty_relocatable_for(&overlay_elf, e_machine)?;
    } else {
        let ld_status = run_real_linker(
            &pruned,
            &layout_script,
            &overlay_elf,
            xtensa_layout.as_ref(),
            &argv,
            &stripped_libs,
            base.manifest.entry_symbol.as_str(),
            &assumed_names,
        )?;
        if !ld_status.success() {
            bail!(
                "real linker exited with {ld_status} (see {})",
                work_dir.display()
            );
        }
        verify_assumed_names(&overlay_elf, &assumed_names)?;
    }
    let t_link = t_link_start.elapsed();

    // Single-ELF output: combine base + overlay directly into cargo's
    // `-o` path. The standalone overlay.elf stays in work_dir for
    // debugging / inspection, but cargo + everything downstream sees one
    // self-contained executable. The `graft combine` subcommand still
    // exists for explicit invocation against arbitrary base/overlay
    // pairs (snapshots, archived overlays, …), but no longer required
    // for the normal build loop.
    let t_combine_start = std::time::Instant::now();
    let combine_stats = crate::combine::combine(&base_path, &overlay_elf, &output)
        .with_context(|| {
            format!(
                "combine base={} overlay={} -> {}",
                base_path.display(),
                overlay_elf.display(),
                output.display()
            )
        })?;
    let t_combine = t_combine_start.elapsed();

    // Sidecar with the combine stats so callers (tests, dev driver) can
    // see the trampoline count etc. without parsing the linker's stderr
    // — rustc captures+filters linker stderr so eprintln won't reach
    // them. JSON-on-disk next to overlay.elf in work_dir.
    let stats_path = work_dir.join("combine-stats.json");
    write_combine_stats(&stats_path, &combine_stats)?;

    let summary = format!(
        "graft overlay: base {} symhash · overlay {} objs / {} sections · \
         closure {} sections · \
         pruned {} objs / {} sections / {} abs-rewrites · \
         combined {} bytes (overlay payload {} @ {:#x}, {} trampolines) · \
         scan {:.1?} · closure {:.1?} · prune {:.1?} · link {:.1?} · combine {:.1?} · \
         total {:.1?}\n\
         overlay.elf: {}\n",
        base.by_symhash.len(),
        scan.objects.len(),
        scan.graph.nodes.len(),
        closure.closure.len(),
        pruned.len(),
        kept_sec_total,
        abs_rewrites_total,
        combine_stats.combined_size,
        combine_stats.overlay_load_size,
        combine_stats.overlay_vaddr,
        combine_stats.trampolines.len(),
        t_scan,
        t_closure,
        t_prune,
        t_link,
        t_combine,
        t_start.elapsed(),
        overlay_elf.display(),
    );
    eprint!("{summary}");
    if let Ok(p) = std::env::var("GRAFT_LOG") {
        let _ = std::fs::write(&p, {
            let mut body = summary.into_bytes();
            body.extend_from_slice(&format_closure_dump(&scan, &closure));
            body
        });
    }

    Ok(())
}

/// Compose the scan inputs, split into eager and deferred buckets:
///   - **eager**: `.o` and `.rlib` paths that always parse fully.
///   - **deferred**: `.a` archives (direct paths from argv + every
///     `-l<name>` resolved against `-L` paths or the driver sysroot)
///     where members get parsed only when reachability demands it.
/// `-l<name>` flags that don't resolve are skipped (e.g. linker-script
/// stubs that ld processes directly); the link step still gets them
/// via forwarded argv.
pub(crate) fn resolve_scan_inputs(
    args: &crate::argv::LinkArgs,
    driver: &Path,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut eager: Vec<PathBuf> = Vec::new();
    let mut deferred: Vec<PathBuf> = Vec::new();
    for p in &args.inputs {
        let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
        match ext {
            "a" => deferred.push(p.clone()),
            _ => eager.push(p.clone()),
        }
    }
    for name in &args.libs {
        let resolved = crate::argv::resolve_lib(name, &args.library_paths)
            .or_else(|| crate::argv::resolve_lib_via_driver(name, driver));
        if let Some(path) = resolved {
            deferred.push(path);
        }
    }
    (eager, deferred)
}

fn work_dir_for(output: &Path) -> PathBuf {
    // `target/debug/app` → `target/debug/app.graft-work`
    let mut p = output.as_os_str().to_os_string();
    p.push(".graft-work");
    PathBuf::from(p)
}

struct PrunedEntry {
    path: PathBuf,
    kept_sections: usize,
    abs_rewrites: usize,
    /// (name, assumed_address) for every reloc this prune resolved
    /// through `base_symtab` (the channel-of-last-resort). Aggregated
    /// across all entries and used for post-link verify.
    assumed_names: Vec<(String, u64)>,
    /// If true, this entry is a filtered archive (`.a` file) graft
    /// emitted from pruned members. Wrap with
    /// `-Wl,--whole-archive .. -Wl,--no-whole-archive` when invoking
    /// ld so it doesn't require a symbol table (the `ar` crate
    /// doesn't emit one) and so every pruned member is force-loaded
    /// (graft already filtered to closure-touching members; demand-
    /// loading is unnecessary).
    is_archive: bool,
}

fn prune_all(
    scan: &ScanResult,
    closure: &Closure,
    base_resolver: &prune::BaseResolver<'_>,
    work_dir: &Path,
) -> Result<Vec<PrunedEntry>> {
    // Group closure sections by object.
    let mut by_obj: HashMap<u32, HashSet<u32>> = HashMap::new();
    for &nid in &closure.closure {
        let nm = &scan.graph.nodes[nid as usize];
        for seg in &nm.segments {
            by_obj.entry(seg.object).or_default().insert(seg.section);
        }
    }

    // First pass: prune each object whose sections appear in the
    // closure. We split into two buckets: loose pruned `.o`s
    // (member_name=None inputs) and per-archive grouped pruned
    // members. The grouping is keyed on the archive's source path so
    // every member of `libdeploy.rlib` gets bundled together.
    struct LooseEntry {
        path: PathBuf,
        kept_sections: usize,
        abs_rewrites: usize,
        assumed_names: Vec<(String, u64)>,
        is_archive: bool,
    }
    struct ArchiveMember {
        member_name: String,
        bytes: Vec<u8>,
        kept_sections: usize,
        abs_rewrites: usize,
        assumed_names: Vec<(String, u64)>,
    }
    let mut loose: Vec<LooseEntry> = Vec::new();
    let mut archives: HashMap<PathBuf, Vec<ArchiveMember>> = HashMap::new();
    for (obj_idx, keep_set) in by_obj {
        let input = &scan.inputs[obj_idx as usize];
        let parsed = &scan.objects[obj_idx as usize];
        let p = prune::prune_object(&input.bytes, parsed.tu_id, &keep_set, base_resolver)
            .with_context(|| format!("prune {}", input.label()))?;
        match input.member_name.as_deref() {
            None => {
                // Loose .o input. Write to work_dir as a standalone file.
                let stem = input
                    .source_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("obj")
                    .to_string();
                let filename = format!("{obj_idx:04}_{stem}");
                let path = work_dir.join(&filename);
                std::fs::write(&path, &p.bytes)
                    .with_context(|| format!("write {}", path.display()))?;
                loose.push(LooseEntry {
                    path,
                    kept_sections: p.kept_sections,
                    abs_rewrites: p.abs_rewrites,
                    assumed_names: p.assumed_names,
                    is_archive: false,
                });
            }
            Some(member_name) => {
                // Archive member. Stash for second-pass bundling.
                archives
                    .entry(input.source_path.clone())
                    .or_default()
                    .push(ArchiveMember {
                        member_name: member_name.replace('/', "_"),
                        bytes: p.bytes,
                        kept_sections: p.kept_sections,
                        abs_rewrites: p.abs_rewrites,
                        assumed_names: p.assumed_names,
                    });
            }
        }
    }

    // Second pass: bundle archive members into one filtered archive
    // per source archive. ld sees only what the closure asked for —
    // members of the original archive that no closure section
    // referenced are not in the filtered version, so ld can't pull
    // them in via `-u SYM` / KEEP() / undefined-symbol resolution.
    // Filename matches the source archive's basename so
    // `forwarded_link_args` (which strips direct-path archive inputs
    // via `is_input`) doesn't double-feed the original.
    let mut out: Vec<PrunedEntry> = Vec::new();
    for entry in loose {
        out.push(PrunedEntry {
            path: entry.path,
            kept_sections: entry.kept_sections,
            abs_rewrites: entry.abs_rewrites,
            assumed_names: entry.assumed_names,
            is_archive: entry.is_archive,
        });
    }
    for (source_path, members) in archives {
        let basename = source_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("filtered");
        let path = work_dir.join(basename);
        let kept_sections: usize = members.iter().map(|m| m.kept_sections).sum();
        let abs_rewrites: usize = members.iter().map(|m| m.abs_rewrites).sum();
        let assumed_names: Vec<(String, u64)> = members
            .iter()
            .flat_map(|m| m.assumed_names.iter().cloned())
            .collect();
        let payload: Vec<(&str, &[u8])> = members
            .iter()
            .map(|m| (m.member_name.as_str(), m.bytes.as_slice()))
            .collect();
        write_filtered_archive(&path, &payload)
            .with_context(|| format!("write filtered archive {}", path.display()))?;
        out.push(PrunedEntry {
            path,
            kept_sections,
            abs_rewrites,
            assumed_names,
            is_archive: true,
        });
    }
    // Sort for deterministic linker invocation order.
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Build a Unix `ar`-format archive at `path` containing each pruned
/// member as an entry. The `ar` crate handles long-name tables
/// (BSD-style `#1/<n>` extended names) for member names that don't
/// fit ar's 16-byte header field — graft's archive members from
/// rustc rlibs typically have names like
/// `deploy-<hash>.<cgu>.<seq>.rcgu.o` that exceed 16 bytes.
fn write_filtered_archive(path: &Path, members: &[(&str, &[u8])]) -> Result<()> {
    let f = std::fs::File::create(path)
        .with_context(|| format!("create {}", path.display()))?;
    let mut builder = ar::Builder::new(f);
    for (name, bytes) in members {
        let header = ar::Header::new(name.as_bytes().to_vec(), bytes.len() as u64);
        builder
            .append(&header, *bytes)
            .with_context(|| format!("append {name} to {}", path.display()))?;
    }
    Ok(())
}

fn write_combine_stats(path: &Path, stats: &crate::combine::Stats) -> Result<()> {
    use std::fmt::Write;
    let mut s = String::new();
    write!(
        s,
        "{{\"combined_size\":{},\"overlay_load_size\":{},\"overlay_vaddr\":{},\"trampolines\":[",
        stats.combined_size, stats.overlay_load_size, stats.overlay_vaddr,
    )
    .unwrap();
    for (i, t) in stats.trampolines.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        write!(
            s,
            "{{\"name\":{:?},\"base_addr\":{},\"overlay_addr\":{}}}",
            t.name, t.base_addr, t.overlay_addr,
        )
        .unwrap();
    }
    s.push_str("]}\n");
    std::fs::write(path, s).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_empty_relocatable_for(path: &Path, e_machine: u16) -> Result<()> {
    use object::{Architecture, BinaryFormat, Endianness, write::Object as WObject};
    let arch = match e_machine {
        object::elf::EM_X86_64 => Architecture::X86_64,
        object::elf::EM_XTENSA => Architecture::Xtensa,
        m => bail!("write_empty_relocatable_for: unsupported e_machine={m:#x}"),
    };
    let out = WObject::new(BinaryFormat::Elf, arch, Endianness::Little);
    let bytes = out.write().map_err(|e| anyhow!("write empty ET_REL: {e}"))?;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Compute the virtual address where overlay's output sections land:
/// first 4KB-aligned vaddr past the highest end of any allocated
/// section in base.elf. Page-aligned so partial-flash diffs (pageflash)
/// land cleanly on sector boundaries; close enough to base that the
/// trampoline jump (`jmp rel32` on x86-64, multi-instruction long-jump
/// on xtensa) is always in range.
fn compute_overlay_base_addr(base_path: &Path) -> Result<u64> {
    use object::{Object, ObjectSection, SectionFlags};
    let bytes =
        std::fs::read(base_path).with_context(|| format!("read {}", base_path.display()))?;
    let elf = object::File::parse(&*bytes).context("parse base ELF for layout")?;
    let mut max_end: u64 = 0;
    for sec in elf.sections() {
        let alloc = matches!(
            sec.flags(),
            SectionFlags::Elf { sh_flags } if (sh_flags & u64::from(object::elf::SHF_ALLOC)) != 0
        );
        if !alloc {
            continue;
        }
        max_end = max_end.max(sec.address() + sec.size());
    }
    if max_end == 0 {
        bail!("base ELF {} has no allocated sections", base_path.display());
    }
    const PAGE: u64 = 0x1000;
    Ok((max_end + PAGE - 1) & !(PAGE - 1))
}

/// Splice-mode layout for non-xtensa hosted targets (x86_64 today).
/// Places overlay's `.text*` at the slack `.text` vaddr and overlay's
/// `.rodata*` / `.data.rel.ro*` at the slack `.rodata` vaddr. Discards
/// any non-text/rodata alloc sections — splice mode covers only the
/// two slack-reserved regions, so anything else (`.data`, `.bss`,
/// `.eh_frame_hdr`, …) must come from base. ASSERTs guard against
/// silent slack overflow at link time.
fn write_overlay_layout_ld_splice(path: &Path, slack: &Slack) -> Result<()> {
    // ASSERT-on-overflow lives at the top level (outside SECTIONS) so
    // it sees the placement-final symbols `_graft_text_end` /
    // `_graft_rodata_end`. Inside SECTIONS, top-level ASSERTs get
    // rejected by some ld versions.
    let script = format!(
        "/* graft overlay layout (splice): place .text/.rodata at \
         base's reserved slack vaddrs. */\n\
         SECTIONS {{\n\
         \x20  . = {text_start:#x};\n\
         \x20  .text : {{ *(.text .text.*) }}\n\
         \x20  _graft_text_end = .;\n\
         \x20  . = {rodata_start:#x};\n\
         \x20  .rodata : {{ *(.rodata .rodata.* .rodata..L*) }}\n\
         \x20  .data.rel.ro : {{ *(.data.rel.ro .data.rel.ro.* .data.rel.ro..L*) }}\n\
         \x20  _graft_rodata_end = .;\n\
         \x20  /DISCARD/ : {{ *(.eh_frame .eh_frame_hdr .gcc_except_table* \
         .data .data.* .bss .bss.* COMMON .note.* .comment .gnu_debuglink) }}\n\
         }}\n\
         ASSERT(_graft_text_end <= {text_end:#x}, \"overlay .text overflows GRAFT_TEXT_SLACK\")\n\
         ASSERT(_graft_rodata_end <= {rodata_end:#x}, \"overlay .rodata overflows GRAFT_RODATA_SLACK\")\n",
        text_start = slack.text_start,
        text_end = slack.text_start + slack.text_len,
        rodata_start = slack.rodata_start,
        rodata_end = slack.rodata_start + slack.rodata_len,
    );
    std::fs::write(path, script).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_overlay_layout_ld(path: &Path, base_addr: u64) -> Result<()> {
    // Bump-allocate overlay's alloc sections starting at `base_addr`.
    // Orphan rules let us glob by prefix, so new `.text.<symbol>`
    // sections need no explicit entry.
    //
    // Unwind info gap (deferred): `.eh_frame` is currently dropped by
    // `prune::prune_object` before ld ever sees it, because rustc
    // emits one `.eh_frame` per .o covering every `.text.*` in that
    // .o — keeping it would leave FDE relocs pointing at sections the
    // pruner removed, which ld would reject. A proper fix needs
    // per-FDE splitting so only FDEs whose target `.text` is in the
    // closure survive. Until that lands, overlay code's `.eh_frame`
    // is synthesized on-the-fly by ld from what little escapes
    // pruning, and a panic through overlay IPs won't unwind (runtime
    // will abort). The fixture deliberately exercises no panic path.
    // `.gcc_except_table` has the same shape and the same gap.
    // `.eh_frame_hdr` is discarded because it would be a partial
    // header covering only overlay's FDEs and would confuse the
    // runtime unwinder if ever discovered via a new GNU_EH_FRAME phdr.
    let script = format!(
        "/* graft overlay layout: disjoint from base's address range. */\n\
         SECTIONS {{\n\
         \x20  . = {base_addr:#x};\n\
         \x20  .text             : {{ *(.text .text.*) }}\n\
         \x20  .rodata           : {{ *(.rodata .rodata.* .rodata..L*) }}\n\
         \x20  .data.rel.ro      : {{ *(.data.rel.ro .data.rel.ro.* .data.rel.ro..L*) }}\n\
         \x20  .data             : {{ *(.data .data.*) }}\n\
         \x20  .bss              : {{ *(.bss .bss.* COMMON) }}\n\
         \x20  .eh_frame         : {{ KEEP(*(.eh_frame)) }}\n\
         \x20  .gcc_except_table : {{ *(.gcc_except_table .gcc_except_table.*) }}\n\
         \x20  /DISCARD/         : {{ *(.eh_frame_hdr .note.* .comment .gnu_debuglink) }}\n\
         }}\n"
    );
    std::fs::write(path, script).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Build a `name → vaddr` map of every defined symbol in base.elf's
/// `.symtab`. Used by prune to resolve overlay reloc targets, and
/// (until lazy-archive walking lands fully) emitted as a global
/// PROVIDE script so ld can resolve UND references inside forwarded
/// `-l<lib>` content that graft doesn't yet expand.
/// First-seen-wins on duplicate names — base occasionally has
/// same-named locals across TUs, but for global-name resolution any
/// of their addresses suffices (ld would have picked one).
/// After overlay link, verify every `assumed_names` entry: walk
/// overlay's output `.symtab`, find each name, and confirm the linker
/// placed it at the address graft assumed. A mismatch means a symbol
/// graft thought was layout-stable actually shifted (e.g., a
/// linker-script `_*_end = .;` whose value depends on overlay's
/// distinct layout). Bail loudly — the rewritten relocs would be
/// pointing at the wrong address.
fn verify_assumed_names(overlay_elf: &Path, assumed: &HashMap<String, u64>) -> Result<()> {
    use object::{Object, ObjectSymbol};
    if assumed.is_empty() {
        return Ok(());
    }
    let bytes = std::fs::read(overlay_elf)
        .with_context(|| format!("read overlay {}", overlay_elf.display()))?;
    let elf = object::File::parse(&*bytes).context("parse overlay ELF for verify")?;
    let mut overlay_addrs: HashMap<String, u64> = HashMap::new();
    for sym in elf.symbols() {
        if sym.is_undefined() {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        // First-write-wins: overlay symtab can repeat names across
        // SHN_ABS anchors and real defs; the real def comes from the
        // ELF's own symtab walk and is what we want to compare.
        overlay_addrs.entry(name.to_string()).or_insert(sym.address());
    }
    let mut mismatches: Vec<(String, u64, Option<u64>)> = Vec::new();
    for (name, &assumed_addr) in assumed {
        match overlay_addrs.get(name) {
            // Skip anchors graft itself wrote (`__graft_assumed_*`).
            // They're at our assumed address by construction.
            _ if name.starts_with("__graft_assumed_") => {}
            Some(&overlay_addr) if overlay_addr == assumed_addr => {}
            Some(&overlay_addr) => {
                mismatches.push((name.clone(), assumed_addr, Some(overlay_addr)));
            }
            None => {
                // Symbol not in overlay's symtab. Common: the name is
                // SHN_ABS-defined by overlay's linker script and ld
                // resolves UND refs to it but doesn't put a separate
                // entry in `.symtab`. This is the same case base.symtab
                // is meant to bridge, and there's no way to verify
                // independently; trust the snapshot.
            }
        }
    }
    if !mismatches.is_empty() {
        let mut msg = String::from(
            "graft overlay verify: assumed-stable names shifted between base and overlay link:\n",
        );
        for (name, assumed_addr, overlay_addr) in &mismatches {
            use std::fmt::Write;
            let _ = match overlay_addr {
                Some(a) => writeln!(
                    &mut msg,
                    "  {name}: assumed {assumed_addr:#x}, overlay placed at {a:#x}",
                ),
                None => writeln!(&mut msg, "  {name}: assumed {assumed_addr:#x}, missing"),
            };
        }
        // Heuristic: if the failing list contains canonically-esp-idf
        // layout symbols or aggregator brackets, this is the
        // early-trampoline / shared-layout case. Point the reader at
        // the design note. These names show up when
        // `call_start_cpu0`'s literal pool is in the closure
        // (bss-clear, flash MMU, vector table — see `cpu_start.c.obj`)
        // or when overlay's startup walks `__init_array`.
        const LAYOUT_TELLTALES: &[&str] = &[
            "_bss_start", "_bss_end",
            "_rtc_bss_start", "_rtc_bss_end",
            "_ext_ram_bss_start", "_ext_ram_bss_end",
            "_instruction_reserved_start", "_instruction_reserved_end",
            "_rodata_reserved_start", "_rodata_reserved_end",
            "_vector_table",
            "__init_array_start", "__init_array_end",
            "__fini_array_start", "__fini_array_end",
            "__preinit_array_start", "__preinit_array_end",
        ];
        let hit_layout_symbol = mismatches
            .iter()
            .any(|(n, _, _)| LAYOUT_TELLTALES.contains(&n.as_str()));
        if hit_layout_symbol {
            use std::fmt::Write;
            let _ = writeln!(
                &mut msg,
                "\nThe failing names include esp-idf layout symbols defined by the\n\
                 linker script as `_bss_start = .;` / `_vector_table = ABSOLUTE(.);`\n\
                 / etc. Their values are layout-derived and the overlay's pruned\n\
                 link produces different values from base's. graft does not yet\n\
                 patch the overlay's linker scripts to PROVIDE base's values back\n\
                 — see docs/13-early-trampoline.md for the design and what's\n\
                 left to implement before early-trampoline / init-code-change\n\
                 handling is real.",
            );
        }
        bail!("{msg}");
    }
    Ok(())
}


fn run_real_linker(
    pruned: &[PrunedEntry],
    layout: &Path,
    output: &Path,
    xtensa: Option<&XtensaLayout>,
    rustc_argv: &[String],
    stripped_libs: &HashSet<String>,
    entry_symbol: &str,
    assumed_names: &HashMap<String, u64>,
) -> Result<std::process::ExitStatus> {
    // Invoke the gcc-style driver rustc gave us (gcc handles `-Wl,…`,
    // `-l<lib>`, default-library suppression, etc. for both
    // bare-metal and hosted targets — base mode's passthrough also
    // goes through it). Forward rustc's full link argv so overlay
    // sees the same `-l esp_rom_sys` (whose stub library is a
    // linker script PROVIDING ROM addresses), `-Wl,--gc-sections`,
    // `-nostartfiles`, etc. that base saw. The only divergence from
    // rustc's argv is: we replace inputs with the pruned `.o`s and
    // we redirect `-o` to overlay.elf.
    let real = std::env::var("GRAFT_REAL_LD").unwrap_or_else(|_| "cc".into());
    let mut cmd = Command::new(&real);
    cmd.arg("-o").arg(output);

    // Forced-root for --gc-sections (which rustc enables by default
    // for release builds). The overlay link has no `_start` —
    // entry_symbol is the only thing that needs to survive ld's GC,
    // since combine's trampoline is what actually reaches it.
    // Without this, --gc-sections sees no roots and nukes the
    // entire pruned input.
    cmd.arg(format!("-Wl,-u,{entry_symbol}"));

    // Force every assumed-stable name into overlay's symtab so the
    // post-link verify can find it. Without `--undefined=<name>`,
    // ld may resolve UND refs via SHN_ABS in script + omit a
    // separate symtab entry, which makes verify silently fall back
    // to "trust the snapshot" rather than catching layout-dependent
    // drift.
    for name in assumed_names.keys() {
        cmd.arg(format!("-Wl,--undefined={name}"));
    }

    // Suppress gcc's implicit startup-file injection (`crti.o`,
    // `crtbegin.o`, `crtend.o`, `crtn.o`). Those carry `_init`/`_fini`
    // which the linker script's KEEP(*(.init.text)) etc. would pull
    // into a `.iram0.vectors` segment in overlay's output — content
    // base already has, ending up appended as a new PT_LOAD past
    // base's IRAM. Overlay never invokes init/fini chains; base does
    // that once at boot. -nostartfiles is per-overlay-link only;
    // base's link still gets them through normal gcc behavior.
    cmd.arg("-nostartfiles");

    // No PROVIDE-based symbol resolution: every base-bound reloc in
    // graft's pruned `.o`s is already encoded as
    // `(__graft_const, base_vaddr + addend)` at prune time, and every
    // `-l<name>` archive whose content reaches the closure has been
    // walked + emitted as a filtered `.a`. Linker scripts that
    // PROVIDE() defaults for would-be-UND base symbols are harmless:
    // nothing references those names anymore.

    if let Some(x) = xtensa {
        // Prepend our work_dir so ld's INCLUDE "memory.x" /
        // INCLUDE "esp32s3.x" inside linkall.x find our mutated
        // copies first. The mutated esp32s3.x INCLUDEs
        // `graft_blockers.ld` after memory.x has declared
        // `iram_seg` / `dram_seg`, which we couldn't do with a
        // command-line `-T` (script ordering puts that before
        // memory.x).
        cmd.arg("-L").arg(&x.work_dir);
    } else {
        // x86 path: layout script bumps everything from OVERLAY_BASE_ADDR.
        cmd.arg("-T").arg(layout);
    }

    // Forward rustc's link args (sans inputs, `-o`, walked-`-l`s and
    // every `-L`).
    for a in crate::argv::forwarded_link_args(rustc_argv, stripped_libs) {
        cmd.arg(a);
    }

    // Pruned closure inputs replace rustc's original inputs.
    // Archive entries get bracketed with `--whole-archive` so ld
    // accepts our `ar`-crate-emitted archives without a symbol-table
    // index (we generate none) and so every pruned member is force-
    // loaded — graft already filtered the archive to closure-touching
    // members, so demand-loading would be redundant.
    for p in pruned {
        if p.is_archive {
            cmd.arg("-Wl,--whole-archive");
            cmd.arg(&p.path);
            cmd.arg("-Wl,--no-whole-archive");
        } else {
            cmd.arg(&p.path);
        }
    }
    let status = cmd.status().with_context(|| format!("exec {real}"))?;
    Ok(status)
}

pub struct BaseMetadata {
    pub manifest: GraftManifest,
    /// Content-keyed lookup. Every entry in base's `.graft.symhash`
    /// indexed by its 16-byte symhash (folds stable name + section
    /// trans_hash). Identity is build-invariant: same symhash means
    /// "base has interchangeable bytes for this content", regardless
    /// of CGU re-partition or `.llvm.<id>` suffix drift.
    pub by_symhash: HashMap<crate::hash::Symhash, SymHashEntry>,
    /// Snapshot of base's post-link `.symtab`: name → final address.
    /// Channel-of-last-resort for reloc resolution — used when a
    /// name isn't matched by overlay's scan or by `by_symhash`.
    /// Resolution rewrites relocs to a per-name `__graft_assumed_<hex>`
    /// SHN_ABS anchor at this address, post-link-verified.
    pub by_name: HashMap<String, u64>,
}

fn load_base_metadata(path: &std::path::Path) -> Result<BaseMetadata> {
    use object::{Object, ObjectSymbol};
    let bytes = std::fs::read(path).with_context(|| format!("read base {}", path.display()))?;
    let manifest_bytes = elf_attach::read_section(&bytes, SECTION_MANIFEST)?
        .ok_or_else(|| anyhow!("{}: no {}", path.display(), SECTION_MANIFEST))?;
    let symhash_bytes = elf_attach::read_section(&bytes, SECTION_SYMHASH)?
        .ok_or_else(|| anyhow!("{}: no {}", path.display(), SECTION_SYMHASH))?;

    let manifest = metadata::decode_manifest(manifest_bytes)?;
    if manifest.magic != metadata::GRAFT_MAGIC {
        bail!("{}: bad graft magic", path.display());
    }
    if manifest.version != SCHEMA_VERSION {
        bail!(
            "{}: schema version {} != {}",
            path.display(),
            manifest.version,
            SCHEMA_VERSION
        );
    }

    let entries = metadata::decode_symhash(symhash_bytes)?;
    let mut by_symhash: HashMap<crate::hash::Symhash, SymHashEntry> =
        HashMap::with_capacity(entries.len());
    for e in entries {
        by_symhash.entry(e.symhash).or_insert(e);
    }

    // Walk base.elf's `.symtab` for the channel-of-last-resort
    // (`name → address`) lookup. Done lazily here from the file we've
    // already read — no separate sidecar needed. Captures every
    // defined named symbol the linker resolved: SHN_ABS script
    // absolutes, PROVIDE-defaulted symbols, weak fallbacks,
    // layout-derived `_*_start/_*_end` brackets, anything else base
    // ended up with at link time.
    let elf = object::File::parse(&*bytes)
        .with_context(|| format!("parse {} for symtab snapshot", path.display()))?;
    let mut by_name: HashMap<String, u64> = HashMap::new();
    for sym in elf.symbols() {
        if sym.is_undefined() { continue; }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() { continue; }
        if matches!(
            sym.kind(),
            object::SymbolKind::File | object::SymbolKind::Section,
        ) {
            continue;
        }
        by_name.entry(name.to_string()).or_insert(sym.address());
    }

    Ok(BaseMetadata { manifest, by_symhash, by_name })
}

pub(crate) struct Closure {
    /// Nodes we must include in the overlay link (their trans_hash did
    /// not match base's). Sections matching base by trans_hash are
    /// skipped at the closure-walk boundary; their content is reached
    /// via base addresses, encoded as SHN_ABS+addend at prune time.
    pub closure: Vec<NodeId>,
}

fn compute_closure(
    scan: &ScanResult,
    base: &BaseMetadata,
    roots: &[NodeId],
) -> Result<Closure> {
    let mut closure: Vec<NodeId> = Vec::new();

    // Per-node state: Unknown / Included / Provided. We don't walk into
    // nodes marked Provided — base already satisfies everything reachable
    // from them (by trans_hash).
    #[derive(Copy, Clone, PartialEq, Eq)]
    enum Decision {
        Unknown,
        Included,
        Provided,
    }
    let mut decision = vec![Decision::Unknown; scan.graph.nodes.len()];

    // DFS from every root. ld's gc-sections would start from the same
    // set; the Provided/Included classification terminates branches
    // whose trans_hash matches base (i.e., base's already-linked
    // version is interchangeable with whatever overlay would emit).
    let mut stack: Vec<NodeId> = roots.to_vec();
    while let Some(nid) = stack.pop() {
        if decision[nid as usize] != Decision::Unknown {
            continue;
        }
        if classify_provided(nid, scan, base) {
            decision[nid as usize] = Decision::Provided;
        } else {
            decision[nid as usize] = Decision::Included;
            closure.push(nid);
            for &succ in &scan.graph.edges[nid as usize] {
                if decision[succ as usize] == Decision::Unknown {
                    stack.push(succ);
                }
            }
        }
    }

    closure.sort();
    Ok(Closure { closure })
}

/// Returns true iff this section can be satisfied by base — at least
/// one defined symbol's `symhash_of(stable_name, trans_hash)` matches
/// an entry in `base.by_symhash`. Sections with no matchable symbol
/// must be Included (no address to point a reloc at).
fn classify_provided(nid: NodeId, scan: &ScanResult, base: &BaseMetadata) -> bool {
    let nm = &scan.graph.nodes[nid as usize];
    let th: TransHash = scan.trans_hash[nid as usize];
    let dump_path = std::env::var("GRAFT_DEBUG_MISMATCH").ok();

    let mut any_match = false;
    let mut any_defined_symbol = false;
    for sym in &nm.defined_symbols {
        any_defined_symbol = true;
        let symhash = crate::hash::symhash_of(crate::hash::stable_name_part(&sym.name), &th);
        if base.by_symhash.contains_key(&symhash) {
            any_match = true;
        } else if let Some(p) = dump_path.as_ref() {
            let oh: String = symhash[..8].iter().map(|b| format!("{b:02x}")).collect();
            let tag = match sym.bind {
                SymbolBind::Local => 'L',
                _ => 'G',
            };
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .and_then(|mut f| {
                    std::io::Write::write_all(
                        &mut f,
                        format!(
                            "{tag} {} symhash={oh} (no base match)\n",
                            sym.name,
                        )
                        .as_bytes(),
                    )
                });
        }
    }
    any_defined_symbol && any_match
}

fn format_closure_dump(scan: &ScanResult, c: &Closure) -> Vec<u8> {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "closure sections ({}):", c.closure.len());
    for &nid in &c.closure {
        let nm = &scan.graph.nodes[nid as usize];
        let tag = nm.aggregator_id.unwrap_or("");
        for seg in &nm.segments {
            let obj = &scan.objects[seg.object as usize];
            let sec = &obj.sections[seg.section as usize];
            let label = scan.inputs[seg.object as usize].label();
            let prefix = if tag.is_empty() { String::new() } else { format!("<agg:{tag}> ") };
            let len = seg.bytes_in(&obj.sections).len();
            let range_tag = match seg.range {
                Some((off, _)) => format!("@+{off}"),
                None => String::new(),
            };
            let _ = writeln!(
                s,
                "  [{nid}] {prefix}{label} :: {}{range_tag} ({len} bytes)",
                sec.name,
            );
        }
    }
    s.into_bytes()
}

/// Read base.elf's `e_machine` field (bytes 18..20, little-endian).
fn base_e_machine(bytes: &[u8]) -> Result<u16> {
    if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" {
        bail!("base ELF too short or not ELF");
    }
    Ok(u16::from_le_bytes(bytes[18..20].try_into().unwrap()))
}

/// Layout adjustments for xtensa overlay link: a mutated `memory.x`
/// dropped in `work_dir`, and the original esp-hal `-L` paths so ld's
/// `INCLUDE` falls through for everything else.
pub struct XtensaLayout {
    pub work_dir: PathBuf,
    pub search_paths: Vec<PathBuf>,
    pub slack: Slack,
}

#[derive(Debug, Clone, Copy)]
pub struct Slack {
    /// Start vaddr of `GRAFT_TEXT_SLACK` in base.elf — overlay's
    /// `irom_seg` ORIGIN.
    pub text_start: u64,
    /// Length of `GRAFT_TEXT_SLACK` in bytes.
    pub text_len: u64,
    /// Start vaddr of `GRAFT_RODATA_SLACK` in base.elf — overlay's
    /// `drom_seg` ORIGIN.
    pub rodata_start: u64,
    /// Length of `GRAFT_RODATA_SLACK` in bytes.
    pub rodata_len: u64,
    /// Start vaddr of `GRAFT_DATA_SLACK` in base.elf — overlay's
    /// `dram_seg` ORIGIN. Carved out of base's `.data` so overlay's
    /// writable static data can splice in without colliding with
    /// base's `.data`/`.bss`/`.stack`.
    pub data_start: u64,
    /// Length of `GRAFT_DATA_SLACK` in bytes.
    pub data_len: u64,
}

/// Look up `GRAFT_TEXT_SLACK` and `GRAFT_RODATA_SLACK` in base.elf's
/// symtab and return their (vaddr, size). The fixture defines them
/// as `[u8; N]` statics with `link_section` attributes that funnel
/// them into base's `.text` / `.rodata` output sections (via the
/// existing `*(.rodata .rodata.*)` / `*(.text .literal.*)` wildcards),
/// so they sit *inside* base's already-mapped IROM/DROM segments.
/// Overlay then aims its `.text` / `.rodata` at those vaddrs and the
/// bundle post-processor splices the bytes into base.img.
fn compute_slack(base_bytes: &[u8]) -> Result<Slack> {
    use object::{Object, ObjectSymbol};
    let elf = object::File::parse(base_bytes).context("parse base ELF for xtensa slack")?;
    let mut text: Option<(u64, u64)> = None;
    let mut rodata: Option<(u64, u64)> = None;
    let mut data: Option<(u64, u64)> = None;
    for sym in elf.symbols() {
        let Ok(name) = sym.name() else { continue };
        match name {
            "GRAFT_TEXT_SLACK" => text = Some((sym.address(), sym.size())),
            "GRAFT_RODATA_SLACK" => rodata = Some((sym.address(), sym.size())),
            "GRAFT_DATA_SLACK" => data = Some((sym.address(), sym.size())),
            _ => {}
        }
    }
    let (text_start, text_len) = text.ok_or_else(|| {
        anyhow!(
            "base ELF: GRAFT_TEXT_SLACK symbol not found \
             (synthetic slack `.o` must be in base's link argv)"
        )
    })?;
    let (rodata_start, rodata_len) = rodata.ok_or_else(|| {
        anyhow!(
            "base ELF: GRAFT_RODATA_SLACK symbol not found \
             (synthetic slack `.o` must be in base's link argv)"
        )
    })?;
    let (data_start, data_len) = data.ok_or_else(|| {
        anyhow!(
            "base ELF: GRAFT_DATA_SLACK symbol not found \
             (synthetic slack `.o` must be in base's link argv)"
        )
    })?;
    if text_start & 3 != 0 || rodata_start & 3 != 0 || data_start & 3 != 0 {
        bail!(
            "GRAFT_*_SLACK must be 4-byte aligned — got \
             irom={text_start:#x}, drom={rodata_start:#x}, dram={data_start:#x}"
        );
    }
    Ok(Slack {
        text_start,
        text_len,
        rodata_start,
        rodata_len,
        data_start,
        data_len,
    })
}

/// Mutate esp-hal's `memory.x` so `irom_seg` and `drom_seg` start at
/// the slack addresses (overlay's flash region) instead of base's
/// flash region. Line-based; idempotent re-runs on the same input
/// produce identical output.
fn mutate_memory_x(content: &str, slack: &Slack) -> Result<String> {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(content.len() + 256);
    let mut found_irom = false;
    let mut found_drom = false;
    let mut found_dram = false;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("irom_seg") && trimmed.contains("ORIGIN") {
            writeln!(
                out,
                "  irom_seg ( RX ) : ORIGIN = {:#x}, len = {:#x}",
                slack.text_start, slack.text_len
            )
            .unwrap();
            found_irom = true;
        } else if trimmed.starts_with("drom_seg") && trimmed.contains("ORIGIN") {
            writeln!(
                out,
                "  drom_seg ( R ) : ORIGIN = {:#x}, len = {:#x}",
                slack.rodata_start, slack.rodata_len
            )
            .unwrap();
            found_drom = true;
        } else if trimmed.starts_with("dram_seg") && trimmed.contains("ORIGIN") {
            // Pin overlay's dram_seg to the data slack range. Overlay's
            // `.data`/`.bss`/`.stack` all use this region via the
            // `RWDATA` REGION_ALIAS; .stack and .bss are NOLOAD so
            // they don't touch flash. Only `.data` (PROGBITS) gets
            // bytes spliced into base via combine.
            writeln!(
                out,
                "  dram_seg ( RW ) : ORIGIN = {:#x}, len = {:#x}",
                slack.data_start, slack.data_len
            )
            .unwrap();
            found_dram = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !found_irom {
        bail!("memory.x: no irom_seg ORIGIN line found — esp-hal layout changed?");
    }
    if !found_drom {
        bail!("memory.x: no drom_seg ORIGIN line found — esp-hal layout changed?");
    }
    if !found_dram {
        bail!("memory.x: no dram_seg ORIGIN line found — esp-hal layout changed?");
    }
    Ok(out)
}

/// Strip the `.rotext_dummy` SECTIONS clause (and its
/// `INSERT BEFORE .text;`) from esp-hal's `esp32s3.x`.
///
/// Why: the clause exists in base's link to skip past the flash
/// bytes occupied by `.rodata` so `.text` doesn't end up reading
/// rodata content (DROM and IROM map the same physical flash on
/// ESP32-S3). It rounds the skip up to `ALIGN(0x10000) + 0x20`,
/// which costs ~38 KB of zero-padding in the image.
///
/// For overlay's link this is unnecessary by construction:
///   - Overlay's `.rodata` lives in the slack DROM region, past
///     base's DROM end.
///   - Overlay's `.text`  lives in the slack IROM region, past
///     base's IROM end.
///   - The two slack regions correspond to disjoint flash ranges,
///     so DROM-reading-text overlap is impossible.
///
/// The cache requirement (`paddr % 64KB == vaddr % 64KB`) is
/// satisfied by *contiguity* with base's segment: when espflash
/// merges base's IROM segment with overlay's, paddr and vaddr
/// advance in lockstep, so any aligned-on-base position remains
/// aligned. We just need overlay's `.text` 4-byte slack-aligned
/// past base's IROM end and the merged segment is well-formed.
///
/// `_rotext_reserved_start` is only referenced inside esp32s3.x
/// itself, so dropping the clause is safe — confirmed by grep
/// across all esp-hal scripts. Idempotent.
fn mutate_esp32s3_x(content: &str) -> Result<String> {
    let block_start = content
        .find("SECTIONS {\n  .rotext_dummy")
        .ok_or_else(|| anyhow!("esp32s3.x: no `.rotext_dummy` SECTIONS clause"))?;
    let insert = "INSERT BEFORE .text;\n";
    let block_end_rel = content[block_start..]
        .find(insert)
        .ok_or_else(|| anyhow!("esp32s3.x: no `INSERT BEFORE .text` after `.rotext_dummy`"))?;
    let block_end = block_start + block_end_rel + insert.len();

    let mut out = String::with_capacity(content.len());
    out.push_str(&content[..block_start]);
    out.push_str(
        "/* graft overlay: .rotext_dummy removed — overlay's .text and \
         .rodata land in disjoint slack ranges, so the DROM/IROM-overlap \
         skip is unnecessary. */\n",
    );
    let after_dummy = &content[block_end..];

    // Insert `INCLUDE "graft_blockers.ld"` BEFORE the SECTIONS block
    // that pulls in `rwtext.x` / `rwdata.x`. ld's section-ordering is
    // script order within a memory region, so emitting the blocker
    // first guarantees it lands at iram_seg/dram_seg ORIGIN — without
    // needing INSERT BEFORE (which fails when the target section is
    // empty after --gc-sections).
    let anchor = "SECTIONS {\n  INCLUDE \"rwtext.x\"";
    let split = after_dummy.find(anchor).ok_or_else(|| {
        anyhow!("esp32s3.x: no `SECTIONS {{ INCLUDE \"rwtext.x\"` block to anchor blocker before")
    })?;
    out.push_str(&after_dummy[..split]);
    out.push_str("INCLUDE \"graft_blockers.ld\"\n\n");
    out.push_str(&after_dummy[split..]);
    Ok(out)
}

/// Two flavors of esp32s3 link layout we know how to mutate. esp-hal
/// ships its own `memory.x` + `esp32s3.x`; esp-idf-sys ships
/// `memory.ld` + `sections.ld` (preprocessed from `.in` templates).
/// Region names, address arithmetic, and the rodata-dummy section
/// all differ. `detect` picks based on which files appear in the
/// linker's `-L` paths; same -L set carries through to the real
/// linker untouched.
#[derive(Debug)]
enum Layout {
    EspHal {
        memory_x: PathBuf,
        esp32s3_x: PathBuf,
    },
    EspIdf {
        memory_ld: PathBuf,
        sections_ld: PathBuf,
    },
}

impl Layout {
    fn detect(argv: &[String]) -> Result<(Self, Vec<PathBuf>)> {
        let paths = collect_l_paths(argv);
        // Prefer esp-idf when both candidates exist (esp-idf-sys can
        // ship esp-hal scripts as transitive dev-deps; the
        // authoritative chain is the one rustc actually `-T`s).
        let memory_ld = paths.iter().find_map(|p| {
            let c = p.join("memory.ld");
            c.exists().then_some(c)
        });
        let sections_ld = paths.iter().find_map(|p| {
            let c = p.join("sections.ld");
            c.exists().then_some(c)
        });
        if let (Some(memory_ld), Some(sections_ld)) = (memory_ld, sections_ld) {
            return Ok((Self::EspIdf { memory_ld, sections_ld }, paths));
        }
        let memory_x = paths.iter().find_map(|p| {
            let c = p.join("memory.x");
            c.exists().then_some(c)
        });
        let esp32s3_x = paths.iter().find_map(|p| {
            let c = p.join("esp32s3.x");
            c.exists().then_some(c)
        });
        if let (Some(memory_x), Some(esp32s3_x)) = (memory_x, esp32s3_x) {
            return Ok((Self::EspHal { memory_x, esp32s3_x }, paths));
        }
        bail!(
            "no recognized linker-script layout found in {} -L path(s) — \
             expected esp-idf (memory.ld + sections.ld) or esp-hal \
             (memory.x + esp32s3.x)",
            paths.len()
        );
    }
}

fn collect_l_paths(argv: &[String]) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == "-L"
            && let Some(p) = argv.get(i + 1)
        {
            paths.push(PathBuf::from(p));
            i += 2;
            continue;
        }
        if let Some(p) = argv[i].strip_prefix("-L") {
            paths.push(PathBuf::from(p));
        }
        i += 1;
    }
    paths
}

fn setup_xtensa_layout(
    work_dir: &Path,
    base_bytes: &[u8],
    argv: &[String],
) -> Result<XtensaLayout> {
    let slack = compute_slack(base_bytes)?;
    let ram = compute_xtensa_ram_usage(base_bytes)?;
    let (layout, search_paths) = Layout::detect(argv)?;

    match &layout {
        Layout::EspHal { memory_x, esp32s3_x } => {
            let memory_orig = std::fs::read_to_string(memory_x)
                .with_context(|| format!("read {}", memory_x.display()))?;
            let memory_mutated = mutate_memory_x(&memory_orig, &slack)?;
            std::fs::write(work_dir.join("memory.x"), memory_mutated)
                .with_context(|| format!("write {}/memory.x", work_dir.display()))?;

            let esp_orig = std::fs::read_to_string(esp32s3_x)
                .with_context(|| format!("read {}", esp32s3_x.display()))?;
            let esp_mutated = mutate_esp32s3_x(&esp_orig)?;
            std::fs::write(work_dir.join("esp32s3.x"), esp_mutated)
                .with_context(|| format!("write {}/esp32s3.x", work_dir.display()))?;

            let blockers = render_blockers_ld_esp_hal(&ram);
            std::fs::write(work_dir.join("graft_blockers.ld"), blockers)
                .with_context(|| format!("write {}/graft_blockers.ld", work_dir.display()))?;
        }
        Layout::EspIdf { memory_ld, sections_ld } => {
            let memory_orig = std::fs::read_to_string(memory_ld)
                .with_context(|| format!("read {}", memory_ld.display()))?;
            let memory_mutated = mutate_memory_ld(&memory_orig, &slack)?;
            std::fs::write(work_dir.join("memory.ld"), memory_mutated)
                .with_context(|| format!("write {}/memory.ld", work_dir.display()))?;

            let sections_orig = std::fs::read_to_string(sections_ld)
                .with_context(|| format!("read {}", sections_ld.display()))?;
            let sections_mutated = mutate_sections_ld(&sections_orig)?;
            std::fs::write(work_dir.join("sections.ld"), sections_mutated)
                .with_context(|| format!("write {}/sections.ld", work_dir.display()))?;

            let blockers = render_blockers_ld_esp_idf(&ram);
            std::fs::write(work_dir.join("graft_blockers.ld"), blockers)
                .with_context(|| format!("write {}/graft_blockers.ld", work_dir.display()))?;
        }
    }

    Ok(XtensaLayout {
        work_dir: work_dir.to_path_buf(),
        search_paths,
        slack,
    })
}

/// Mutate esp-idf's `memory.ld`: bump `iram0_2_seg` (IROM),
/// `drom0_0_seg` (DROM), and `dram0_0_seg` (DRAM) ORIGINs to the
/// slack vaddrs. Same purpose as `mutate_memory_x` for esp-hal but
/// against esp-idf's region naming.
fn mutate_memory_ld(content: &str, slack: &Slack) -> Result<String> {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(content.len() + 256);
    let mut found_irom = false;
    let mut found_drom = false;
    let mut found_dram = false;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("iram0_2_seg") && trimmed.contains("org") {
            writeln!(
                out,
                "  iram0_2_seg (RX) : org = {:#x}, len = {:#x}",
                slack.text_start, slack.text_len
            )
            .unwrap();
            found_irom = true;
        } else if trimmed.starts_with("drom0_0_seg") && trimmed.contains("org") {
            writeln!(
                out,
                "  drom0_0_seg (R) : org = {:#x}, len = {:#x}",
                slack.rodata_start, slack.rodata_len
            )
            .unwrap();
            found_drom = true;
        } else if trimmed.starts_with("dram0_0_seg") && trimmed.contains("org") {
            writeln!(
                out,
                "  dram0_0_seg (RW) : org = {:#x}, len = {:#x}",
                slack.data_start, slack.data_len
            )
            .unwrap();
            found_dram = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !found_irom {
        bail!("memory.ld: no iram0_2_seg org line found — esp-idf layout changed?");
    }
    if !found_drom {
        bail!("memory.ld: no drom0_0_seg org line found — esp-idf layout changed?");
    }
    if !found_dram {
        bail!("memory.ld: no dram0_0_seg org line found — esp-idf layout changed?");
    }
    Ok(out)
}

/// Mutate esp-idf's `sections.ld`: strip the `.flash_rodata_dummy`
/// (analog of esp-hal's `.rotext_dummy`, ensures DROM/IROM cache
/// alignment by burning rodata-side space equal to .flash.text size)
/// and INCLUDE `graft_blockers.ld` near the start so the IRAM
/// blocker is parsed before `.iram0.text`. The
/// `_flash_rodata_dummy_start = ABSOLUTE(ORIGIN(default_rodata_seg))`
/// ASSERT in memory.ld is gated on `_flash_rodata_dummy_start`
/// existing — replace the dummy clause with a stub that defines
/// the symbol at the slack origin.
fn mutate_sections_ld(content: &str) -> Result<String> {
    // Replace the `.flash_rodata_dummy` body. Keep the section name
    // so the assert in memory.ld still finds `_flash_rodata_dummy_start`,
    // but drop the size-of-flash-text gap (overlay's `.rodata` doesn't
    // span the same range as base's `.text` — it lives in a slack
    // region with a fixed size).
    let block_start = content
        .find(".flash_rodata_dummy (NOLOAD):")
        .ok_or_else(|| anyhow!("sections.ld: no `.flash_rodata_dummy` clause"))?;
    let body_open = content[block_start..]
        .find('{')
        .ok_or_else(|| anyhow!("sections.ld: malformed flash_rodata_dummy (no `{{`)"))?;
    let body_close_rel = content[block_start + body_open..]
        .find('}')
        .ok_or_else(|| anyhow!("sections.ld: malformed flash_rodata_dummy (no `}}`)"))?;
    let body_close = block_start + body_open + body_close_rel;

    let mut out = String::with_capacity(content.len() + 256);
    out.push_str(&content[..block_start + body_open + 1]);
    out.push_str(
        "\n    /* graft overlay: original .flash_rodata_dummy gap removed; \
         overlay's .rodata lands in slack and doesn't need DROM/IROM size \
         alignment with .flash.text. */\n    \
         _flash_rodata_dummy_start = ABSOLUTE(.);\n  ",
    );
    out.push_str(&content[body_close..]);

    // Inject blocker INCLUDE at the top of the SECTIONS{} block (after
    // the opening brace). Matches the position where esp-idf's first
    // section clause appears.
    let sections_open = out
        .find("SECTIONS\n{")
        .or_else(|| out.find("SECTIONS {"))
        .ok_or_else(|| anyhow!("sections.ld: no `SECTIONS {{` block"))?;
    let brace = out[sections_open..]
        .find('{')
        .ok_or_else(|| anyhow!("sections.ld: SECTIONS without `{{`"))?;
    let injection_point = sections_open + brace + 1;
    let mut final_out = String::with_capacity(out.len() + 64);
    final_out.push_str(&out[..injection_point]);
    final_out.push_str("\n  INCLUDE \"graft_blockers.ld\"\n");
    final_out.push_str(&out[injection_point..]);
    Ok(final_out)
}

/// ESP32-S3 IRAM region, per esp-hal `memory.x`:
/// `0x4037_0000 .. 0x4040_0000`. Used to bucket base PT_LOADs.
const ESP32S3_IRAM_RANGE: (u64, u64) = (0x40370000, 0x40400000);

/// Bytes already used by base in IRAM. Counted from `iram_seg`'s
/// lowest base PT_LOAD start to its highest end. Drives the size of
/// the NOLOAD blocker so overlay's `.rwtext` is placed past base's
/// IRAM usage. DRAM doesn't need a blocker because overlay's
/// `dram_seg` is pinned to the data slack vaddr+len (see
/// `mutate_memory_x`); base's `.stack` lives at *its* dram_seg end,
/// not overlay's, so they don't collide.
#[derive(Debug, Clone, Copy)]
pub struct RamUsage {
    pub iram_blocker_bytes: u64,
}

fn compute_xtensa_ram_usage(base_bytes: &[u8]) -> Result<RamUsage> {
    use object::{Object, ObjectSegment};
    let elf = object::File::parse(base_bytes).context("parse base ELF for RAM usage")?;
    let mut iram_lo = u64::MAX;
    let mut iram_hi = 0u64;
    for seg in elf.segments() {
        if seg.size() == 0 {
            continue;
        }
        let s = seg.address();
        let e = s + seg.size();
        if s >= ESP32S3_IRAM_RANGE.0 && e <= ESP32S3_IRAM_RANGE.1 {
            iram_lo = iram_lo.min(s);
            iram_hi = iram_hi.max(e);
        }
    }
    let iram_blocker_bytes = if iram_lo == u64::MAX { 0 } else { iram_hi - iram_lo };
    // 16-byte aligned so the linker has breathing room for ALIGN()s.
    let align_up = |n: u64| (n + 15) & !15;
    Ok(RamUsage {
        iram_blocker_bytes: align_up(iram_blocker_bytes),
    })
}

/// esp-hal blocker: NOLOAD reservation in `iram_seg`. Placement
/// comes from `> iram_seg`; ordering relative to esp-hal's `.rwtext`
/// is handled by `mutate_esp32s3_x` INCLUDEing this script before
/// the SECTIONS block that pulls in `rwtext.x`. (DRAM uses slack-
/// reservation via `mutate_memory_x`; no IRAM-style blocker.)
fn render_blockers_ld_esp_hal(ram: &RamUsage) -> String {
    format!(
        "/* graft overlay (esp-hal): reserve base's used IRAM bytes \
         so overlay's `.rwtext` lands at a fresh vaddr past base. */\n\
         SECTIONS {{\n  \
         .graft_iram_blocker (NOLOAD) : {{\n    \
         . = . + {iram:#x};\n  \
         }} > iram_seg\n\
         }}\n",
        iram = ram.iram_blocker_bytes,
    )
}

/// esp-idf blocker: NOLOAD reservation in `iram0_0_seg`, INSERTed
/// BEFORE `.iram0.vectors` (the first section in iram0_0_seg in
/// esp-idf's sections.ld). Same effect as the esp-hal blocker — eat
/// base's used IRAM so overlay's IRAM clauses land past it.
fn render_blockers_ld_esp_idf(ram: &RamUsage) -> String {
    format!(
        "/* graft overlay (esp-idf): reserve base's used IRAM bytes \
         so overlay's `.iram0.text` / `.iram0.vectors` etc. land at \
         fresh vaddrs past base. */\n\
         .graft_iram_blocker (NOLOAD) : {{\n  \
         . = . + {iram:#x};\n\
         }} > iram0_0_seg\n",
        iram = ram.iram_blocker_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutate_memory_x_replaces_three_lines() {
        let input = "\
RESERVE_ICACHE = 0x8000;
MEMORY
{
  vectors_seg ( RX )     : ORIGIN = 0x40378000, len = 0x400
  irom_seg ( RX )        : ORIGIN = 0x42000020, len = 32M - 0x20
  drom_seg ( R )         : ORIGIN = 0x3C000020, len = 32M - 0x20
  dram_seg ( RW )        : ORIGIN = 0x3FC88000, len = 0x53700
  rtc_fast_seg(RWX) : ORIGIN = 0x600fe000, len = 8k
}
";
        let slack = Slack {
            text_start: 0x4201_7000,
            text_len: 0x10000,
            rodata_start: 0x3C00_2000,
            rodata_len: 0x10000,
            data_start: 0x3FC8_A000,
            data_len: 0x1000,
        };
        let out = mutate_memory_x(input, &slack).unwrap();
        assert!(out.contains("irom_seg ( RX ) : ORIGIN = 0x42017000"));
        assert!(out.contains("drom_seg ( R ) : ORIGIN = 0x3c002000"));
        assert!(out.contains("dram_seg ( RW ) : ORIGIN = 0x3fc8a000"));
        assert!(out.contains("vectors_seg ( RX )     : ORIGIN = 0x40378000"));
        assert!(out.contains("rtc_fast_seg(RWX) : ORIGIN = 0x600fe000"));
    }

    #[test]
    fn mutate_memory_x_errors_if_lines_missing() {
        let input = "MEMORY { ram (RW) : ORIGIN = 0, len = 1k }\n";
        let slack = Slack {
            text_start: 0,
            text_len: 0x10000,
            rodata_start: 0,
            rodata_len: 0x10000,
            data_start: 0,
            data_len: 0x1000,
        };
        assert!(mutate_memory_x(input, &slack).is_err());
    }

    #[test]
    fn mutate_esp32s3_x_drops_rotext_dummy_and_injects_blockers_include() {
        let input = "\
INCLUDE exception.x

SECTIONS {
  .rotext_dummy (NOLOAD) :
  {
    . = . + SIZEOF(.rodata);
    . = ALIGN(0x10000) + 0x20;
    _rotext_reserved_start = .;
  } > ROTEXT
}
INSERT BEFORE .text;

SECTIONS {
  INCLUDE \"rwtext.x\"
  INCLUDE \"rwdata.x\"
}
INCLUDE \"text.x\"
";
        let out = mutate_esp32s3_x(input).unwrap();
        // The actual SECTIONS clause and INSERT directive are gone
        // (the explanatory comment retains the term `.rotext_dummy`,
        // which is fine — ld doesn't interpret comments).
        assert!(!out.contains(".rotext_dummy (NOLOAD)"));
        assert!(!out.contains("INSERT BEFORE .text;"));
        // Other content preserved.
        assert!(out.contains("INCLUDE exception.x"));
        assert!(out.contains("INCLUDE \"text.x\""));
        // Blocker INCLUDE lands BEFORE the SECTIONS block that pulls
        // in rwtext.x — that's how ld's first-in-region ordering picks
        // the blocker as the leading clause in iram_seg / dram_seg.
        let blocker_pos = out.find("INCLUDE \"graft_blockers.ld\"").unwrap();
        let rwtext_pos = out.find("INCLUDE \"rwtext.x\"").unwrap();
        assert!(blocker_pos < rwtext_pos);
    }

    #[test]
    fn mutate_esp32s3_x_errors_on_unrecognized_layout() {
        assert!(mutate_esp32s3_x("INCLUDE foo.x\n").is_err());
    }
}
