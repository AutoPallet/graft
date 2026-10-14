//! Overlay mode: re-link, pruned against a prior base build.
//!
//! Pipeline:
//!   1. Parse argv                       (argv::parse)
//!   2. Load base metadata               (from `GRAFT_BASE_ELF`)
//!   3. Hash + graph overlay's inputs    (scan::run)
//!   4. Compute closure                  (reachability walk from `main`,
//!                                        with per-section trans_hash
//!                                        match against base's section table)
//!   5. Prune each input `.o`            (separate `prune` module; base-bound
//!                                        relocs become UND anchor references)
//!   6. Synthesize the base-map object   (basemap.rs: map sections at base's
//!                                        layout define the anchors; docs/worklogs/15)
//!   7. Exec real linker                 (pruned .o's + base map, into slack)
//!   8. Package                          (write overlay.elf)
//!
//! Steps 1–4 live here; pruning in `prune.rs`, the map object in
//! `basemap.rs`; step 7 shells out to the real `ld` via `$GRAFT_REAL_LD`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, anyhow, bail};

use crate::argv;
use crate::elf_attach;
use crate::graph::NodeId;
use crate::hash::TransHash;
use crate::metadata::{self, GraftManifest, SCHEMA_VERSION, SECTION_MANIFEST, SECTION_SECTIONS};
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
    let base_path: PathBuf = std::env::var("GRAFT_BASE_ELF")
        .map(PathBuf::from)
        .map_err(|_| anyhow!("GRAFT_BASE_ELF not set"))?;
    run_with_base(argv, base_path)
}

/// Overlay link against an explicit base ELF. Plain `GRAFT=overlay`
/// resolves `GRAFT_BASE_ELF` first; auto mode passes its snapshot
/// path directly.
pub(crate) fn run_with_base(argv: Vec<String>, base_path: PathBuf) -> Result<()> {
    let t_start = std::time::Instant::now();

    // Mirror base mode's `--ldproxy-cwd` handling so relative archive
    // paths from esp-idf-sys (e.g. `esp-idf/xtensa/libxtensa.a`)
    // resolve the same way base saw them.
    if let Some(cwd) = crate::base::extract_flag(&argv, "--ldproxy-cwd") {
        std::env::set_current_dir(&cwd)
            .with_context(|| format!("chdir to --ldproxy-cwd {cwd}"))?;
    }

    let argv = argv::expand_response_files(&argv)?;
    let driver = crate::argv::driver_path(&argv);
    let linker_argv = argv::driver_link_argv(&argv, &driver)?;
    let link_args = argv::parse(&linker_argv);
    let output = link_args
        .output
        .clone()
        .ok_or_else(|| anyhow!("no -o <path> in argv"))?;

    let mut base = load_base_metadata(&base_path)?;

    // Argv guard: base recorded its link argv's flag surface
    // (argv::semantic_flags — inputs / -o / -L / -l excluded; the scan
    // captures those by content). Any other flag change (-Wl,--defsym,
    // a -T script swap, a --wrap addition, …) alters link semantics
    // invisibly to the content hashes, so a mismatch refuses before
    // the scan; auto converts that into a full relink.
    let cur_flags = crate::argv::semantic_flags(&linker_argv);
    if cur_flags != base.manifest.argv_flags {
        bail!(
            "overlay refused: linker flags changed since the base link \
             ({}) — graft cannot prove flag-equivalence, so the recorded \
             base layout may not match what these flags would produce. A \
             full relink is required; GRAFT=auto does this automatically.",
            crate::argv::flag_surface_diff(&base.manifest.argv_flags, &cur_flags),
        );
    }
    // Script-content guard: the flag surface records -T script NAMES;
    // an in-place edit (memory.x PROVIDE/KEEP/placement changes) needs
    // the content hashes. Computed over the expanded linker argv, before
    // graft's own layout-script additions — same basis as base.
    let cur_scripts = crate::argv::script_content_hashes(&linker_argv, &link_args.library_paths);
    if cur_scripts != base.manifest.script_hashes {
        bail!(
            "overlay refused: a -T linker script's content changed since the \
             base link (same names, different bytes) — PROVIDE/KEEP/placement \
             semantics may differ from the recorded base layout. A full relink \
             is required; GRAFT=auto does this automatically."
        );
    }
    // Entry-symbol guard: the trampoline cut (which function the
    // overlay redirects) is baked into base at link time. A changed
    // GRAFT_ENTRY_SYMBOL would otherwise succeed while silently
    // keeping the old cut.
    if let Ok(env_entry) = std::env::var("GRAFT_ENTRY_SYMBOL")
        && !env_entry.is_empty()
        && env_entry != base.manifest.entry_symbol
    {
        bail!(
            "overlay refused: GRAFT_ENTRY_SYMBOL={env_entry} but base was linked \
             with entry symbol {:?} — the trampoline cut is baked into the base. \
             A full relink is required; GRAFT=auto does this automatically.",
            base.manifest.entry_symbol,
        );
    }

    let scan_inputs = resolve_scan_inputs(&link_args)?;
    let t_scan_start = std::time::Instant::now();
    let scan = scan::run_ordered(
        &scan_inputs,
        &link_args.undefined,
        &link_args.wrapped,
        Some(base.manifest.entry_symbol.as_str()),
    )
    .context("overlay pre-scan")?;
    let t_scan = t_scan_start.elapsed();

    // Weak/weak-diverged names: ld binds the first weak def in link
    // order; graft's index is content-tiebroken for cross-scan
    // stability. The two are irreconcilable (rlib member order churns
    // per rebuild), and tracking a body ld didn't bind makes edits to
    // the ld-bound body invisible to callers' hashes — the stale-bind
    // class. Overlay mode refuses; base mode (plain ld semantics)
    // only warns.
    if !scan.graph.weak_diverged_referenced.is_empty() {
        bail!(
            "overlay refused: {} weak symbol(s) have multiple weak \
             definitions with differing content and no strong \
             override — ld's bind is link-order-dependent and graft \
             cannot track it soundly: {}",
            scan.graph.weak_diverged_referenced.len(),
            scan.graph.weak_diverged_referenced.join(", ")
        );
    }


    // esp-idf's linker scripts mark `.flash.rodata` with SHF_TLS (a
    // workaround for ld's IROM/DROM vaddr-overlap error), leaving a
    // fake megabyte-scale PT_TLS covering all of DROM. Real ELF TLS
    // cannot exist without SHF_TLS *input* sections; when the scan
    // sees none, the segment is that script artifact — drop TLS
    // handling wholesale instead of marking every rodata anchor
    // STT_TLS and pinning slack to a template that isn't one.
    let tls_nids = tls_node_ids(&scan);
    if base.tls.is_some() && tls_nids.is_empty() {
        eprintln!(
            "graft overlay: base has a PT_TLS but no input section is SHF_TLS — \
             treating it as the esp-idf rodata-overlap artifact (TLS handling off)"
        );
        base.tls = None;
    }

    if let Some(p) = crate::debug_flags::value("dump-graph")?
        && !p.is_empty()
    {
        if let Err(e) = crate::debug_dump::dump_graph(std::path::Path::new(&p), &scan) {
            eprintln!("graft overlay: GRAFT_DEBUG dump-graph write {p} failed: {e}");
        }
    }

    // Lazy walk (xtensa only): base's link relaxed code, so channel-2
    // positional anchors must translate interior offsets through the
    // recorded transform fates. Non-relaxing targets skip the read,
    // the walker, and the pre-pass entirely — every recorded placement
    // was byte-verified at base time, so identity holds.
    let base_elf_bytes: Option<Vec<u8>> = if base.e_machine == object::elf::EM_XTENSA {
        Some(std::fs::read(&base_path).with_context(|| format!("read {}", base_path.display()))?)
    } else {
        None
    };
    let walker = match &base_elf_bytes {
        Some(bytes) => Some(
            crate::relax::walker::Walker::new(
                &scan,
                &base.by_section,
                bytes,
                object::Architecture::Xtensa,
            )
            .map_err(|e| anyhow!("lazy walk init: {e}"))?,
        ),
        None => None,
    };

    let t_closure_start = std::time::Instant::now();
    let roots = roots::find_roots(&scan, &base, &link_args)?;
    let closure = compute_closure_fixpoint(&scan, &base, &roots, walker.as_ref())?;
    let t_closure = t_closure_start.elapsed();

    // Boot guard. The manifest's boot fingerprint is the trans_hash of
    // the node defining the ELF-entry symbol; with edges into the
    // trampoline symbol cut, it covers everything reachable from boot
    // EXCEPT the redirectable subtree — crt, the pre-main constructor
    // walk and its .init_array aggregates, fini. None of that can take
    // effect through an overlay (only the entry symbol is trampolined),
    // so drift there refuses; auto converts it into a full relink.
    if let Some(boot) = &base.manifest.boot {
        let cur = scan
            .graph
            .symbols
            .resolve_global(&boot.symbol)
            .map(|(nid, _)| scan.trans_hash[nid as usize]);
        if cur != Some(boot.trans_hash) {
            bail!(
                "overlay refused: content reachable from boot ({}) changed \
                 outside the entry symbol's subtree — pre-main/crt code cannot \
                 be redirected, so the change would never take effect. A full \
                 relink is required; GRAFT=auto does this automatically.",
                boot.symbol
            );
        }
    }

    // xtensa vector guard: the overlay layout emits `.iram0.vectors`
    // as NOLOAD (its script fill would otherwise alias base's data —
    // see `mutate_sections_ld`), so re-emitted vector code would be
    // silently discarded. Changed vectors require a full base rebuild.
    if base.e_machine == object::elf::EM_XTENSA {
        for &nid in &closure.closure {
            for seg in &scan.graph.nodes[nid as usize].segments {
                let name =
                    &scan.objects[seg.object as usize].sections[seg.section as usize].name;
                if name.contains("Vector.") || name == ".entry.text" || name.contains(".UserEnter")
                {
                    bail!(
                        "closure re-emits interrupt-vector section {name} — vectors \
                         can't live in overlay slack (VECBASE points at base's table). \
                         Rebuild the base instead."
                    );
                }
            }
        }
    }

    // Scratch dir next to the output path. Cleaned and recreated each
    // run so stale pruned .o's from a prior invocation don't confuse
    // the real linker.
    let work_dir = work_dir_for(&output);
    if work_dir.exists() {
        let _ = std::fs::remove_dir_all(&work_dir);
    }
    std::fs::create_dir_all(&work_dir)
        .with_context(|| format!("create {}", work_dir.display()))?;

    // Disposition resolver: translates the scan's recorded per-reloc
    // resolutions (`graph.reloc_targets`) into prune emissions against
    // base's section table. The hash graph, the closure walk, and
    // reloc disposition all consume the SAME resolution — see
    // `resolve.rs` for the channel cascade.
    let closure_nids: HashSet<NodeId> = closure.closure.iter().copied().collect();
    let mutable_ths = mutable_trans_hashes(&scan);
    // Channel-1b defense set: every pool node (xtensa). A pool target
    // reaching dispose outside the closure means the walk's
    // force-include rule and disposition disagree — bail, never anchor.
    let pool_nids: HashSet<NodeId> = if base.e_machine == object::elf::EM_XTENSA {
        (0..scan.graph.nodes.len() as NodeId)
            .filter(|&n| is_literal_pool(n, &scan))
            .collect()
    } else {
        HashSet::new()
    };
    let resolver_wrapped: HashSet<String> = link_args.wrapped.iter().cloned().collect();
    // Count how many anchors the walk actually re-homed — the reference-corpus
    // failure mode was exactly these, so surface them in the summary.
    let walk_translated = std::cell::Cell::new(0usize);
    // Every node that reaches channel-2 positional resolution (the
    // unverified anchor path) is recorded here — `positional_anchor`
    // routes ALL such anchors, on every target, through `translate`, so
    // wrapping it captures the exact set to byte-check post-prune (see
    // anchor_verify.rs). The name-pin (2a) and external (4) channels
    // return an Anchor directly and never call translate.
    let anchored_nodes = std::cell::RefCell::new(HashSet::<NodeId>::new());
    let translate: Box<crate::resolve::TranslateFn<'_>> = match &walker {
        Some(w) => {
            let counter = &walk_translated;
            let anchored = &anchored_nodes;
            Box::new(move |nid, q| {
                anchored.borrow_mut().insert(nid);
                let r = w.query(nid, q);
                if matches!(r, Ok(crate::resolve::Translation::Mapped(_))) {
                    counter.set(counter.get() + 1);
                }
                r
            })
        }
        None => {
            let anchored = &anchored_nodes;
            Box::new(move |nid, q| {
                anchored.borrow_mut().insert(nid);
                crate::resolve::identity_translate(nid, q)
            })
        }
    };
    let resolver = crate::resolve::Resolver {
        trans_hash: &scan.trans_hash,
        reloc_targets: &scan.graph.reloc_targets,
        closure_nids: &closure_nids,
        mutable_ths: &mutable_ths,
        wrapped: &resolver_wrapped,
        by_section: &base.by_section,
        ambiguous_sections: &base.ambiguous_sections,
        by_name: &base.by_name,
        by_name_ambiguous: &base.by_name_ambiguous,
        translate: &*translate,
        pool_nids: &pool_nids,
        tls_range: base.tls.map(|t| (t.vaddr, t.vaddr + t.memsz)),
        tls_nids: &tls_nids,
    };

    // Prune each source object; collect the pruned-.o paths.
    let t_prune_start = std::time::Instant::now();
    // Hosted x86: pruned objects also keep their unwind sections (FDE
    // coverage in the combined image — see ehframe.rs). Unwind stays
    // x86-only: the panic=abort embedded targets have no unwinder and
    // no PT_GNU_EH_FRAME to merge into.
    let keep_unwind = base.e_machine == object::elf::EM_X86_64;
    // Both targets: pruned objects keep their `.debug_*` sections
    // (source-level debug info for re-emitted code — see
    // combine::merge_debug_sections). On xtensa this is what makes a
    // coredump/JTAG gdb resolve symbols+lines inside overlaid
    // functions; rcgu debug relocs there are plain R_XTENSA_32, the
    // same absolute S+A shape the concatenation trick relies on.
    let keep_dwarf = matches!(
        base.e_machine,
        object::elf::EM_X86_64 | object::elf::EM_XTENSA
    );
    let pruned = prune_all(&scan, &closure, &resolver, &work_dir, keep_unwind, keep_dwarf)?;
    let t_prune = t_prune_start.elapsed();
    let anchor_rewrites_total: usize = pruned.iter().map(|p| p.anchor_rewrites).sum();
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
            let path = crate::argv::resolve_lib(name, &link_args.library_paths)?;
            let canon = std::fs::canonicalize(&path).unwrap_or(path);
            scan.walked_archives.contains(&canon).then(|| name.clone())
        })
        .collect();

    // Overlay is a **full** static link — every symbol it references is
    // either defined in the closure's own pruned .o's or resolved to a
    // constant base-derived address through a `__graft_assumed_<vaddr>`
    // anchor. Each such anchor is emitted UND by prune and defined by the
    // synthesized base-map object (`basemap.rs`; docs/worklogs/15) as a section
    // symbol placed at base's layout. Combine just splices the resulting
    // sections into base; no relocation work at combine time.
    //
    // Full-linking requires that base is a non-PIE ET_EXEC so every
    // base-resident byte has a permanent absolute address the base-map
    // object can pin an anchor to. (The fixture's cargo config wires this
    // up via the musl target + `relocation-model=static`.)
    // Splice layout, by target:
    //
    // - x86_64 hosted (e2e/x86 fixture): a SECTIONS block in
    //   `overlay_layout.ld` placing `.text` / `.rodata` at the base-
    //   reserved slack vaddrs (`write_overlay_layout_ld_splice`).
    //
    // - xtensa (esp32s3): pass through esp-hal's linker scripts almost
    //   verbatim; only mutate `memory.x`'s `irom_seg` / `drom_seg`
    //   ORIGIN/len so overlay code/data lands in the slack past base's
    //   used flash. Everything else (alias.x, esp32s3.x, hal-defaults.x,
    //   the per-section INSERT BEFORE machinery) keeps working as-is.
    let base_bytes_for_layout =
        std::fs::read(&base_path).with_context(|| format!("read {}", base_path.display()))?;
    let e_machine = base_e_machine(&base_bytes_for_layout)?;

    // Anchor byte-check (twin of GRAFT_ICF_VERIFY, default on): every
    // channel-2 positional anchor bound overlay to base by trans_hash
    // alone. Re-derive that claim from raw bytes before the real link —
    // a corrupt/stale base.elf or a lying hash refuses here instead of
    // shipping a wrong-address bind. On xtensa the relax walker already
    // reconciled these nodes; on x86 this is a masked byte compare.
    let anchor_arch = match e_machine {
        object::elf::EM_X86_64 => object::Architecture::X86_64,
        object::elf::EM_XTENSA => object::Architecture::Xtensa,
        m => bail!("anchor-verify: unsupported e_machine {m:#x}"),
    };
    {
        let anchored = anchored_nodes.borrow();
        crate::anchor_verify::run(
            crate::anchor_verify::enabled()?,
            &scan,
            &base.by_section,
            &base_bytes_for_layout,
            anchor_arch,
            &anchored,
            walker.as_ref(),
            &output,
        )?;
    }

    let xtensa_layout = if e_machine == object::elf::EM_XTENSA {
        Some(setup_xtensa_layout(&work_dir, &base_bytes_for_layout, &argv)?)
    } else {
        None
    };
    // overlay_layout.ld is always passed to ld (run_real_linker
    // unconditionally adds `-T overlay_layout.ld`). Splice is the only
    // mode, so its contents differ only by target:
    //   - xtensa: empty stub; layout comes from linkall.x + memory.x.
    //   - x86 (and other hosted): SECTIONS placing .text/.rodata at the
    //     base-reserved slack vaddrs.
    // Base-map object: defines every `__graft_assumed_<vaddr>` the
    // pruned objects reference — section symbols in map sections
    // placed at base's layout (positional), SHF_TLS map sections for
    // template vaddrs, SHN_ABS for out-of-image constants (ROM). See
    // `basemap.rs` / docs/worklogs/15.
    let slack = compute_slack(&base_bytes_for_layout)?;
    let mut anchors: Vec<(u64, bool)> = pruned
        .iter()
        .flat_map(|p| p.anchors.iter().copied())
        .collect();
    anchors.sort_unstable();
    anchors.dedup();
    let closure_has_tls = closure.closure.iter().any(|nid| tls_nids.contains(nid));
    let need_tls_maps = closure_has_tls || anchors.iter().any(|&(_, tls)| tls);
    let tls_spec = if need_tls_maps {
        let Some(t) = base.tls else {
            bail!(
                "overlay touches thread-local storage but base has no PT_TLS \
                 template — nothing to anchor TLS against"
            );
        };
        let Some((hole_start, hole_len)) = slack.tls else {
            bail!(
                "overlay touches thread-local storage but base has no \
                 GRAFT_TLS_SLACK (rebuild base with this graft)"
            );
        };
        Some(crate::basemap::TlsMapSpec {
            start: t.vaddr,
            end: t.vaddr + t.memsz,
            hole_start,
            hole_end: hole_start + hole_len,
            align: t.align,
        })
    } else {
        None
    };
    let base_map = if anchors.is_empty() && tls_spec.is_none() {
        None
    } else {
        // Carve-outs: every slack region (overlay content is placed
        // there) plus the PT_TLS span (covered by the TLS maps).
        let mut carve: Vec<(u64, u64)> = vec![
            (slack.text_start, slack.text_len),
            (slack.rodata_start, slack.rodata_len),
            (slack.data_start, slack.data_len),
        ];
        if let Some(t) = base.tls {
            carve.push((t.vaddr, t.memsz));
        }
        let arch = crate::slack::architecture_from_e_machine(e_machine)?;
        let map = crate::basemap::synthesize(arch, &anchors, &base.load_spans, &carve, tls_spec)?;
        let map_path = work_dir.join("graft_base_map.o");
        std::fs::write(&map_path, &map.object_bytes)
            .with_context(|| format!("write {}", map_path.display()))?;
        Some((map_path, map.sections))
    };

    let layout_script = work_dir.join("overlay_layout.ld");
    let map_sections: &[crate::basemap::MapSection] =
        base_map.as_ref().map(|(_, s)| s.as_slice()).unwrap_or(&[]);
    if xtensa_layout.is_some() {
        std::fs::write(&layout_script, b"/* xtensa: linkall.x carries the layout. */\n")
            .with_context(|| format!("write {}", layout_script.display()))?;
    } else {
        // Base's `.debug_*` sizes drive the concatenation-address trick
        // (see the debug stanzas in the layout writer).
        let debug_bases = debug_section_bases(&base_bytes_for_layout)?;
        write_overlay_layout_ld_splice(&layout_script, &slack, map_sections, tls_spec, &debug_bases)?;
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
    // docs/worklogs/13-early-trampoline.md.
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
            base_map.as_ref().map(|(p, _)| p.as_path()),
            map_sections,
        )?;
        if !ld_status.success() {
            bail!(
                "real linker exited with {ld_status} (see {})",
                work_dir.display()
            );
        }
        let overlay_bytes = std::fs::read(&overlay_elf)
            .with_context(|| format!("read overlay {}", overlay_elf.display()))?;
        verify_assumed_names(&overlay_bytes, &assumed_names)?;
        if let Some(spec) = tls_spec {
            verify_tls_geometry(&overlay_bytes, &spec, base.tls.unwrap())?;
        }
        // Hosted only: the generated layout script defines the closed
        // set of output sections, so anything outside it is an orphan
        // ld placed by guesswork — refuse. On xtensa the layout comes
        // from linkall.x and combine's live-base landing check remains
        // the guard.
        if xtensa_layout.is_none() {
            check_overlay_sections(&overlay_bytes, &base_bytes_for_layout)?;
        }
        // Stamp which base this overlay binds to, so a standalone
        // `graft combine` against a different base (geometrically
        // plausible, semantically stale everywhere) refuses.
        let stamp = metadata::encode_overlay_stamp(&metadata::OverlayStamp {
            magic: metadata::GRAFT_MAGIC,
            base_abi: base.manifest.base_abi,
        })?;
        let stamped = elf_attach::append_sections(
            &overlay_bytes,
            &[elf_attach::NewSection { name: metadata::SECTION_OVERLAY_STAMP, data: &stamp }],
        )?;
        std::fs::write(&overlay_elf, &stamped)
            .with_context(|| format!("stamp overlay {}", overlay_elf.display()))?;
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
        "graft overlay: base {} sections · overlay {} objs / {} sections · \
         closure {} sections · \
         pruned {} objs / {} sections / {} anchor-rewrites ({} anchors, {} walk-translated) / {} base-assumed (ch3) · \
         combined {} bytes (overlay payload {} @ {:#x}, {} trampolines) · \
         scan {:.1?} · closure {:.1?} · prune {:.1?} · link {:.1?} · combine {:.1?} · \
         total {:.1?}\n\
         overlay.elf: {}\n",
        base.by_section.len(),
        scan.objects.len(),
        scan.graph.nodes.len(),
        closure.closure.len(),
        pruned.len(),
        kept_sec_total,
        anchor_rewrites_total,
        anchors.len(),
        walk_translated.get(),
        assumed_names.len(),
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
    // Append (main resets GRAFT_LOG once at linker-seat entry) so this
    // summary doesn't clobber notes appended earlier in the same run.
    if let Ok(p) = std::env::var("GRAFT_LOG") {
        if let Ok(mut f) =
            std::fs::OpenOptions::new().create(true).append(true).open(&p)
        {
            use std::io::Write;
            let _ = f.write_all(summary.as_bytes());
            let _ = f.write_all(&format_closure_dump(&scan, &closure));
        }
    }

    Ok(())
}

/// Resolve library flags without changing their positions relative to explicit
/// paths, repeated archives, or group delimiters.
pub(crate) fn resolve_scan_inputs(
    args: &crate::argv::LinkArgs,
) -> Result<Vec<crate::scan::ScanInput>> {
    use crate::argv::LinkInput;
    use crate::scan::ScanInput;
    if args.whole_archive {
        bail!(
            "graft: link argv uses --whole-archive, which force-loads archive \
             members the scan's demand-load model would never see — the graph \
             and boot fingerprint would silently omit them. Unsupported; use \
             GRAFT=passthrough (or unset GRAFT) for this link."
        );
    }
    let mut inputs = Vec::new();
    let mut libraries = HashMap::new();
    for input in &args.ordered_inputs {
        match input {
            LinkInput::Path(path) => inputs.push(ScanInput::File(path.clone())),
            LinkInput::Library(name) => {
                let resolved = libraries.entry(name).or_insert_with(|| {
                    crate::argv::resolve_lib(name, &args.library_paths)
                });
                if let Some(path) = resolved { inputs.push(ScanInput::File(path.clone())); }
            }
            LinkInput::StartGroup => inputs.push(ScanInput::StartGroup),
            LinkInput::EndGroup => inputs.push(ScanInput::EndGroup),
        }
    }
    Ok(inputs)
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
    anchor_rewrites: usize,
    /// (name, assumed_address) for every reloc this prune resolved
    /// through `base_symtab` (the channel-of-last-resort). Aggregated
    /// across all entries and used for post-link verify.
    assumed_names: Vec<(String, u64)>,
    /// `(vaddr, tls)` anchors this entry references; unioned across
    /// entries to synthesize the base-map object.
    anchors: Vec<(u64, bool)>,
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
    resolver: &crate::resolve::Resolver<'_>,
    work_dir: &Path,
    keep_unwind: bool,
    keep_dwarf: bool,
) -> Result<Vec<PrunedEntry>> {
    // Group closure sections by object.
    let mut by_obj: HashMap<u32, HashSet<u32>> = HashMap::new();
    for &nid in &closure.closure {
        let nm = &scan.graph.nodes[nid as usize];
        for seg in &nm.segments {
            by_obj.entry(seg.object).or_default().insert(seg.section);
        }
    }

    // Unwind coverage for re-emitted code (keep_unwind, hosted x86):
    // every pruned object additionally keeps its `.eh_frame` /
    // `.gcc_except_table*` sections. These are physical keep-set additions, NOT closure
    // members — closure semantics (and every hash) are untouched. An
    // rcgu's `.eh_frame` is object-granular and references *all* of the
    // object's functions; prune's normal reloc disposition sorts the
    // targets out: kept text wires internally (FDE pc = slack address),
    // unchanged text anchors to base's copy (FDE pc = base address —
    // redundant coverage that combine's slack filter drops from the
    // merged lookup table), and the CIE's personality slot
    // (`.data.DW.ref.rust_eh_personality`) anchors like any other
    // unchanged data. ld then FDE-edits and builds the overlay's
    // `.eh_frame_hdr` exactly as it would in a full link.
    // Debug info rides the same way (keep_dwarf, x86 + xtensa): every
    // pruned object keeps its
    // `.debug_*` sections (whole CUs — subsetting DIE trees is
    // dsymutil-class surgery and unnecessary: relocs into sections the
    // closure didn't keep tombstone to 0, exactly what ld does for
    // gc'd code, and base's own DWARF still describes those unchanged
    // functions). `.debug_gdb_scripts` is excluded — it's SHF_ALLOC,
    // runtime-loaded, and closure-managed like any other section.
    if keep_unwind || keep_dwarf {
        for (&obj_idx, keep_set) in by_obj.iter_mut() {
            for (idx, sec) in scan.objects[obj_idx as usize].sections.iter().enumerate() {
                let unwind = sec.name == ".eh_frame"
                    || sec.name.starts_with(".eh_frame.")
                    || sec.name.starts_with(".gcc_except_table");
                let dwarf =
                    sec.name.starts_with(".debug_") && sec.name != ".debug_gdb_scripts";
                if (keep_unwind && unwind) || (keep_dwarf && dwarf) {
                    keep_set.insert(idx as u32);
                }
            }
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
        anchor_rewrites: usize,
        assumed_names: Vec<(String, u64)>,
        anchors: Vec<(u64, bool)>,
        is_archive: bool,
    }
    struct ArchiveMember {
        member_name: String,
        bytes: Vec<u8>,
        kept_sections: usize,
        anchor_rewrites: usize,
        assumed_names: Vec<(String, u64)>,
        anchors: Vec<(u64, bool)>,
    }
    let mut loose: Vec<LooseEntry> = Vec::new();
    let mut archives: HashMap<PathBuf, Vec<ArchiveMember>> = HashMap::new();
    for (obj_idx, keep_set) in by_obj {
        let input = &scan.inputs[obj_idx as usize];
        let dispose = move |q: &crate::resolve::RelocQuery<'_>| resolver.dispose(obj_idx, q);
        let p = prune::prune_object(&input.bytes, &keep_set, &dispose)
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
                    anchor_rewrites: p.anchor_rewrites,
                    assumed_names: p.assumed_names,
                    anchors: p.anchors,
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
                        anchor_rewrites: p.anchor_rewrites,
                        assumed_names: p.assumed_names,
                        anchors: p.anchors,
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
            anchor_rewrites: entry.anchor_rewrites,
            assumed_names: entry.assumed_names,
            anchors: entry.anchors,
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
        let anchor_rewrites: usize = members.iter().map(|m| m.anchor_rewrites).sum();
        let assumed_names: Vec<(String, u64)> = members
            .iter()
            .flat_map(|m| m.assumed_names.iter().cloned())
            .collect();
        let anchors: Vec<(u64, bool)> = members
            .iter()
            .flat_map(|m| m.anchors.iter().copied())
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
            anchor_rewrites,
            assumed_names,
            anchors,
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

/// Splice-mode layout for non-xtensa hosted targets (x86_64 today).
/// Places overlay's `.text*` at the slack `.text` vaddr, overlay's
/// `.rodata*` / `.data.rel.ro*` at the slack `.rodata` vaddr,
/// re-emitted `.data*`/`.bss*` at the slack `.data` vaddr (zero-filled
/// at base link — NOBITS `.bss` gets no splice write and reads the
/// fill as its initial value), re-emitted `.tdata`/`.tbss` in the
/// in-template TLS slack hole, and every base-map section at the base
/// address span it mirrors. Unwind/metadata sections are discarded
/// (overlay unwind is a known deferred gap). ASSERTs guard against
/// silent slack overflow at link time.
///
/// All placements are emitted in ascending address order: ld refuses
/// to move the location counter backwards, and map sections (which
/// mirror base content *around* the slack carve-outs) interleave with
/// the slack-placed content blocks.
fn write_overlay_layout_ld_splice(
    path: &Path,
    slack: &Slack,
    maps: &[crate::basemap::MapSection],
    tls: Option<crate::basemap::TlsMapSpec>,
    debug_bases: &[(String, u64)],
) -> Result<()> {
    let mut stanzas: Vec<(u64, String)> = Vec::new();
    stanzas.push((
        slack.text_start,
        format!(
            "  . = {:#x};\n  .text : {{ *(.text .text.*) }}\n  _graft_text_end = .;\n",
            slack.text_start
        ),
    ));
    stanzas.push((
        slack.rodata_start,
        format!(
            "  . = {:#x};\n  .rodata : {{ *(.rodata .rodata.* .rodata..L*) }}\n  \
             .data.rel.ro : {{ *(.data.rel.ro .data.rel.ro.* .data.rel.ro..L*) }}\n  \
             .debug_gdb_scripts : {{ *(.debug_gdb_scripts) }}\n  \
             .gcc_except_table : {{ *(.gcc_except_table .gcc_except_table.*) }}\n  \
             .eh_frame_hdr : {{ KEEP(*(.eh_frame_hdr)) }}\n  \
             .eh_frame : {{ KEEP(*(.eh_frame)) }}\n  \
             _graft_rodata_end = .;\n",
            slack.rodata_start
        ),
    ));
    // Re-emitted mutable statics land in the data slack. `.data`
    // (PROGBITS) splices its initializer bytes; `.bss` (NOBITS, placed
    // after — file-offset rules) gets no splice write and reads the
    // slack's own zero fill as its initial value. `.got`/`.got.plt`
    // are placed explicitly: ld relaxes most GOTPCRELX refs to direct
    // `lea` so the section is usually absent, but a non-relaxable GOT
    // ref would otherwise orphan-place at an ld-chosen address —
    // deterministic placement beats orphan luck (audited by
    // `check_overlay_sections`).
    stanzas.push((
        slack.data_start,
        format!(
            "  . = {:#x};\n  .got : {{ *(.got .got.plt) }}\n  \
             .data : {{ *(.data .data.*) }}\n  \
             .bss : {{ *(.bss .bss.* COMMON) }}\n  _graft_data_end = .;\n",
            slack.data_start
        ),
    ));
    if let Some(t) = tls {
        stanzas.push((
            t.hole_start,
            format!(
                "  . = {:#x};\n  .tdata : {{ *(.tdata .tdata.*) }}\n  \
                 .tbss : {{ *(.tbss .tbss.*) }}\n  _graft_tls_end = .;\n",
                t.hole_start
            ),
        ));
    }
    for ms in maps {
        stanzas.push((
            ms.vaddr,
            format!("  . = {:#x};\n  {} : {{ *({}) }}\n", ms.vaddr, ms.name, ms.name),
        ));
    }
    stanzas.sort_by_key(|&(addr, _)| addr);

    let mut script = String::from(
        "/* graft overlay layout (splice): slack-placed overlay content \
         interleaved with base-map sections, ascending by address. */\n\
         SECTIONS {\n",
    );
    for (_, s) in &stanzas {
        script.push_str(s);
    }
    // Audit collectors: metadata sections the combined image does NOT
    // take from the overlay, gathered into non-alloc (INFO) sections at
    // address 0 instead of being /DISCARD/ed, so `check_overlay_sections`
    // can verify post-link that dropping them is lossless (byte-equal /
    // string-subset against base's counterpart). `(INFO)` keeps them out
    // of every PT_LOAD; combine ignores non-alloc sections, so they ride
    // along in overlay.elf only. The init/fini collector must be EMPTY:
    // ctor/dtor drift is refused upstream by the boot fingerprint, and a
    // non-empty collector here means an entry slipped past it — an
    // appended entry would be silently outside base's baked
    // `__init_array_start/end` walk, so fail the link instead.
    // (`.debug_gdb_scripts` is NOT audited-and-dropped: rustc's `main`
    // shim volatile-loads its first byte at runtime to keep it alive,
    // so it's a closure section that must be placed at a mapped
    // address — it gets an explicit rodata-block stanza above. Moving
    // it to an INFO collector segfaulted the combined image.)
    script.push_str(concat!(
        "  .graft.audit.note.gnu.property 0 (INFO) : { *(.note.gnu.property) }\n",
        "  .graft.audit.note.ABI-tag 0 (INFO) : { *(.note.ABI-tag) }\n",
        "  .graft.audit.initfini 0 (INFO) : { *(.init_array*) *(.fini_array*) \
         *(.preinit_array*) *(.ctors*) *(.dtors*) }\n",
    ));
    // Debug-merge address trick — see `render_debug_stanzas`.
    script.push_str(&render_debug_stanzas(debug_bases));
    // Deliberate discards — each entry has an argument, not a wildcard:
    //   .note.gnu.build-id: ld synthesizes overlay.elf's own id when the
    //     forwarded argv carries --build-id; overlay identity is
    //     graft-composed (blake3(base‖overlay)), the ld one is noise.
    //   .note.GNU-stack: zero-size executable-stack marker for .o files.
    //   .comment / .gnu_debuglink: toolchain version strings / debug-file
    //     pointer; no runtime reads, combined image keeps base's.
    // Anything NOT named here (e.g. an unknown future .note.*) stays an
    // orphan and is refused by check_overlay_sections — "we didn't think
    // about this" must fail loud, not vanish into a wildcard.
    script.push_str(
        "  /DISCARD/ : { *(.note.gnu.build-id) *(.note.GNU-stack) *(.comment) \
         *(.gnu_debuglink) }\n}\n",
    );
    script.push_str(
        "ASSERT(SIZEOF(.graft.audit.initfini) == 0, \"overlay emitted \
         .init_array/.fini_array entries — ctor/dtor changes cannot be overlaid \
         (base's aggregator walk is baked); this should have been refused by the \
         boot fingerprint, please report\")\n",
    );
    use std::fmt::Write as _;
    let _ = writeln!(
        script,
        "ASSERT(_graft_text_end <= {:#x}, \"overlay .text overflows GRAFT_TEXT_SLACK\")",
        slack.text_start + slack.text_len
    );
    let _ = writeln!(
        script,
        "ASSERT(_graft_data_end <= {:#x}, \"overlay .data/.bss overflows GRAFT_DATA_SLACK \
         (raise data= in GRAFT_SLACK_LEN and rebuild base)\")",
        slack.data_start + slack.data_len
    );
    let _ = writeln!(
        script,
        "ASSERT(_graft_rodata_end <= {:#x}, \"overlay .rodata overflows GRAFT_RODATA_SLACK\")",
        slack.rodata_start + slack.rodata_len
    );
    if let Some(t) = tls {
        let _ = writeln!(
            script,
            "ASSERT(_graft_tls_end <= {:#x}, \"overlay thread-locals overflow \
             GRAFT_TLS_SLACK (raise tls= in GRAFT_SLACK_LEN and rebuild base)\")",
            t.hole_end
        );
    }
    std::fs::write(path, script).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Post-link audit of the overlay ELF's section population (hosted
/// splice layout only — the generated script defines a closed set of
/// output sections, which is what makes this check meaningful).
///
/// Two invariants, both "verified, not argued" (same posture as
/// GRAFT_ICF_VERIFY / GRAFT_ANCHOR_VERIFY):
///
/// 1. **Orphan closure.** Every SHF_ALLOC section must be one the
///    layout script explicitly placed. An unknown alloc section means
///    ld orphan-placed it at a guessed address — it may have landed
///    harmlessly inside slack *this time*, but nothing audited that.
///    (Found in the wild: `.debug_gdb_scripts` rode orphan placement
///    into rodata slack for who knows how long — and it's genuinely
///    load-bearing: rustc's `main` shim volatile-loads its first byte,
///    so it now has an explicit placement stanza.)
///
/// 2. **Audit-equality of dropped metadata.** The script collects
///    metadata sections the combined image won't take from the overlay
///    into non-alloc `.graft.audit.*` sections instead of discarding
///    them, and this check proves dropping is lossless: byte-equal to
///    base's counterpart (absent base section == empty).
///    `.note.gnu.property` is the
///    motivating case: it carries x86 CET/IBT feature bits with
///    AND-merge semantics, and the loader enforces from *base's* note —
///    overlay code built under drifted property bits must refuse, and
///    no other guard (toolchain_stamp is recorded-not-enforced, the
///    argv guard covers linker argv only) would catch it.
fn check_overlay_sections(overlay_bytes: &[u8], base_bytes: &[u8]) -> Result<()> {
    use object::{Object, ObjectSection};
    const SHF_ALLOC_U64: u64 = object::elf::SHF_ALLOC as u64;
    // Output sections the generated splice script places (plus the
    // base-map prefix). Keep in lockstep with
    // `write_overlay_layout_ld_splice`.
    const PLACED: &[&str] = &[
        ".text", ".rodata", ".data.rel.ro", ".debug_gdb_scripts", ".gcc_except_table",
        ".eh_frame_hdr", ".eh_frame", ".got", ".data", ".bss", ".tdata", ".tbss",
    ];
    let overlay = object::File::parse(overlay_bytes).context("parse overlay ELF for audit")?;
    let base = object::File::parse(base_bytes).context("parse base ELF for audit")?;
    let base_section = |name: &str| -> Option<Vec<u8>> {
        base.section_by_name(name)
            .and_then(|s| s.data().ok().map(|d| d.to_vec()))
    };
    for sec in overlay.sections() {
        let Ok(name) = sec.name() else { continue };
        let object::SectionFlags::Elf { sh_flags } = sec.flags() else { continue };
        if sh_flags & SHF_ALLOC_U64 != 0 {
            if PLACED.contains(&name) || name.starts_with(".graft.map.") {
                continue;
            }
            bail!(
                "graft overlay audit: alloc section `{name}` ({:#x}+{:#x}) is not \
                 placed by the overlay layout script — ld orphan-placed it at a \
                 guessed address. Add an explicit stanza (placement, audit \
                 collector, or argued /DISCARD/ entry) in \
                 write_overlay_layout_ld_splice before trusting this link.",
                sec.address(),
                sec.size(),
            );
        }
        let Some(counterpart) = name.strip_prefix(".graft.audit.") else { continue };
        let data = sec.data().context("read audit section")?;
        match counterpart {
            "initfini" => {
                // Primary guard is the script ASSERT; this is the
                // belt-and-braces re-check.
                if !data.is_empty() {
                    bail!(
                        "graft overlay audit: overlay emitted {} byte(s) of \
                         .init_array/.fini_array content — ctor/dtor changes \
                         cannot be overlaid (base's aggregator walk is baked)",
                        data.len()
                    );
                }
            }
            base_name => {
                // Note sections: exact byte equality against base's
                // same-named section (absent == empty). ld has already
                // applied its note-merge semantics to the overlay's
                // inputs, so this compares post-merge artifacts — the
                // level the runtime consumes.
                let expect = base_section(&format!(".{base_name}")).unwrap_or_default();
                if data != expect.as_slice() {
                    bail!(
                        "graft overlay audit: .{base_name} differs between overlay \
                         ({} bytes) and base ({} bytes) — the combined image keeps \
                         base's copy, and it would misdescribe overlay code (for \
                         .note.gnu.property: the loader enforces base's CET/IBT \
                         claims on overlay code that was built differently). \
                         Rebuild the base (GRAFT_REBASE=1) with the current \
                         toolchain instead.",
                        data.len(),
                        expect.len(),
                    );
                }
            }
        }
    }
    Ok(())
}

/// After overlay link, verify every `assumed_names` entry: walk
/// overlay's output `.symtab`, find each name, and confirm the linker
/// placed it at the address graft assumed. A mismatch means a symbol
/// graft thought was layout-stable actually shifted (e.g., a
/// linker-script `_*_end = .;` whose value depends on overlay's
/// distinct layout). Bail loudly — the rewritten relocs would be
/// pointing at the wrong address.
fn verify_assumed_names(overlay_bytes: &[u8], assumed: &HashMap<String, u64>) -> Result<()> {
    use object::{Object, ObjectSymbol};
    if assumed.is_empty() {
        return Ok(());
    }
    let elf = object::File::parse(overlay_bytes).context("parse overlay ELF for verify")?;
    // TLS symbols in the linked overlay carry template-relative
    // offsets; assumed addresses are template vaddrs — translate via
    // the overlay's PT_TLS (placed at base's template vaddr by the
    // TLS maps, so the spaces coincide).
    let overlay_tls_vaddr = crate::combine::pt_tls(overlay_bytes)?.map(|t| t.vaddr);
    let mut overlay_addrs: HashMap<String, u64> = HashMap::new();
    for sym in elf.symbols() {
        if sym.is_undefined() {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        let Some(addr) =
            crate::combine::symbol_vaddr(sym.kind(), sym.address(), overlay_tls_vaddr)
        else {
            continue;
        };
        // First-write-wins: overlay symtab can repeat names across
        // graft anchors and real defs; the real def comes from the
        // ELF's own symtab walk and is what we want to compare.
        overlay_addrs.entry(name.to_string()).or_insert(addr);
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
                 — see docs/worklogs/13-early-trampoline.md for the design and what's\n\
                 left to implement before early-trampoline / init-code-change\n\
                 handling is real.",
            );
        }
        bail!("{msg}");
    }
    Ok(())
}

/// TP offsets are functions of (offset-in-template, memsz, align). The
/// TLS maps reproduce base's template geometry so ld's recomputed
/// offsets equal base's — this check makes that assumption loud. A
/// mismatch means a re-emitted/new thread-local spilled the slack hole
/// or demanded a bigger alignment than base's template.
fn verify_tls_geometry(
    overlay_bytes: &[u8],
    spec: &crate::basemap::TlsMapSpec,
    base_tls: crate::combine::PtTls,
) -> Result<()> {
    let Some(ov) = crate::combine::pt_tls(overlay_bytes)? else {
        bail!(
            "overlay link involved TLS (maps at {:#x}..{:#x}) but produced no \
             PT_TLS — layout script regression?",
            spec.start,
            spec.end
        );
    };
    if ov.vaddr != base_tls.vaddr || ov.memsz != base_tls.memsz || ov.align != base_tls.align {
        bail!(
            "overlay PT_TLS geometry diverged from base's — TP offsets would \
             not match.\n  base:    vaddr {:#x} memsz {:#x} align {:#x}\n  \
             overlay: vaddr {:#x} memsz {:#x} align {:#x}\n\
             (a new thread-local needing align > base's template align, or \
             slack-hole overflow, causes this)",
            base_tls.vaddr,
            base_tls.memsz,
            base_tls.align,
            ov.vaddr,
            ov.memsz,
            ov.align,
        );
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
    base_map: Option<&Path>,
    map_sections: &[crate::basemap::MapSection],
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
    // graft's pruned `.o`s is already encoded at prune time as a UND
    // reference to a `__graft_assumed_<vaddr>` anchor, which the
    // synthesized base-map object (`basemap.rs`; docs/worklogs/15) defines at
    // base's layout. Every `-l<name>` archive whose content reaches the
    // closure has been walked + emitted as a filtered `.a`. Linker
    // scripts that PROVIDE() defaults for would-be-UND base symbols are
    // harmless: nothing references those names anymore.

    if let Some(x) = xtensa {
        // Prepend our work_dir so ld's INCLUDE "memory.x" /
        // INCLUDE "esp32s3.x" inside linkall.x find our mutated
        // copies first. The mutated esp32s3.x INCLUDEs
        // `graft_blockers.ld` after memory.x has declared
        // `iram_seg` / `dram_seg`, which we couldn't do with a
        // command-line `-T` (script ordering puts that before
        // memory.x).
        cmd.arg("-L").arg(&x.work_dir);
        // Base-map sections are orphans to linkall.x; pin each at its
        // base address. (On x86 the graft-generated layout script
        // places them instead.)
        for ms in map_sections {
            cmd.arg(format!("-Wl,--section-start={}={:#x}", ms.name, ms.vaddr));
        }
    } else {
        // x86 path: layout script bumps everything from OVERLAY_BASE_ADDR.
        cmd.arg("-T").arg(layout);
    }

    // The base-map object defines every __graft_assumed_* anchor the
    // pruned objects reference. Each map section carries a keep-symbol
    // GC root: TLS maps define PT_TLS geometry and must survive
    // --gc-sections even with zero live references into them.
    if let Some(p) = base_map {
        cmd.arg(p);
        for ms in map_sections {
            cmd.arg(format!("-Wl,--undefined={}", ms.keep_symbol));
        }
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

    // The accumulated argv (forwarded rustc args + pruned inputs +
    // per-anchor `--undefined=` flags) exceeds the OS arg limit on
    // large closures (rust-analyzer deep edit: E2BIG). Hand everything
    // to the driver via a response file — gcc expands `@file` itself,
    // with backslash escaping inside double quotes.
    let rsp_path = output.with_extension("link-args.rsp");
    let mut rsp = String::new();
    for a in cmd.get_args() {
        let s = a.to_string_lossy();
        rsp.push('"');
        for ch in s.chars() {
            if ch == '"' || ch == '\\' {
                rsp.push('\\');
            }
            rsp.push(ch);
        }
        rsp.push_str("\"\n");
    }
    std::fs::write(&rsp_path, &rsp)
        .with_context(|| format!("write {}", rsp_path.display()))?;
    let status = Command::new(&real)
        .arg(format!("@{}", rsp_path.display()))
        .status()
        .with_context(|| format!("exec {real}"))?;
    Ok(status)
}

pub struct BaseMetadata {
    pub manifest: GraftManifest,
    /// Content-keyed section table from base's `.graft.sections`:
    /// `trans_hash → placement (address + placed size)`. A reference
    /// resolves positionally as `by_section[th].addr + in_section_offset`
    /// (offset walk-translated on relaxing targets). Build-invariant:
    /// same `trans_hash` means base has byte-identical section content,
    /// regardless of CGU re-partition or `.llvm.<id>` suffix drift.
    pub by_section: HashMap<TransHash, metadata::Placed>,
    /// `trans_hash`es base saw at more than one distinct address
    /// (content-identical sections it did not fold). Excluded from
    /// `by_section`; a *named* reference to one resolves to base's exact
    /// copy via `by_name` (preserving address identity), a section
    /// reference bails.
    pub ambiguous_sections: HashSet<TransHash>,
    /// Mutable/NOBITS nodes base placed but could not attribute to an
    /// address (`.graft.sections` `unplaced_mutable`). The closure walk
    /// refuses to re-emit these: the miss changed no referrer's hash,
    /// so base's unchanged referrers would keep its copy while the
    /// overlay's changed referrers bound a fresh one — a state fork.
    pub unplaced_mutable: HashSet<TransHash>,
    /// Snapshot of base's post-link `.symtab`: name → final address.
    /// Channel-of-last-resort for reloc resolution — used when a
    /// name isn't matched by overlay's scan or by `by_section`.
    /// Resolution rewrites relocs to a per-name `__graft_assumed_<hex>`
    /// SHN_ABS anchor at this address, post-link-verified.
    ///
    /// Names that base defined at **more than one distinct address**
    /// (same-named STB_LOCAL statics across TUs — common in C-heavy
    /// esp-idf builds) are *excluded* from this map and listed in
    /// `by_name_ambiguous` instead. Channel 3 carries no tu_id, so it
    /// cannot pick the right one; binding to an arbitrary first-seen
    /// address would be a silent wrong-address resolution.
    pub by_name: HashMap<String, u64>,
    /// Names base defined at multiple distinct addresses (see `by_name`).
    /// Channel 3 refuses to resolve these and errors with a precise
    /// diagnostic rather than guessing.
    pub by_name_ambiguous: HashSet<String>,
    /// Base's PT_TLS geometry, if it has a TLS template. Section-table
    /// TLS entries and `by_name` TLS values are template *vaddrs*
    /// (`tls.vaddr + offset`).
    pub tls: Option<crate::combine::PtTls>,
    /// Base's PT_LOAD spans `(vaddr, memsz)` — the map-object intervals.
    pub load_spans: Vec<(u64, u64)>,
    /// Base's ELF machine — gates arch-specific policy (the literal-pool
    /// travel rule is xtensa-only).
    pub e_machine: u16,
}

fn load_base_metadata(path: &std::path::Path) -> Result<BaseMetadata> {
    use object::{Object, ObjectSymbol};
    let bytes = std::fs::read(path).with_context(|| format!("read base {}", path.display()))?;
    let manifest_bytes = elf_attach::read_section(&bytes, SECTION_MANIFEST)?
        .ok_or_else(|| anyhow!("{}: no {}", path.display(), SECTION_MANIFEST))?;
    let sections_bytes = elf_attach::read_section(&bytes, SECTION_SECTIONS)?
        .ok_or_else(|| anyhow!("{}: no {}", path.display(), SECTION_SECTIONS))?;

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
    if manifest.hash_algo_version != metadata::HASH_ALGO_VERSION {
        bail!(
            "{}: trans_hash algorithm version {} != {} — base was hashed \
             by a different graft build; relink the base",
            path.display(),
            manifest.hash_algo_version,
            metadata::HASH_ALGO_VERSION
        );
    }
    let table = metadata::decode_sections(sections_bytes)?;
    let mut by_section: HashMap<TransHash, metadata::Placed> =
        HashMap::with_capacity(table.entries.len());
    for e in &table.entries {
        by_section
            .entry(e.trans_hash)
            .or_insert(metadata::Placed { addr: e.address, out_size: e.out_size });
    }
    let ambiguous_sections: HashSet<TransHash> = table.ambiguous.iter().copied().collect();
    let unplaced_mutable: HashSet<TransHash> = table.unplaced_mutable.iter().copied().collect();

    // Walk base.elf's `.symtab` for the channel-of-last-resort
    // (`name → address`) lookup. Done lazily here from the file we've
    // already read — no separate sidecar needed. Captures every
    // defined named symbol the linker resolved: SHN_ABS script
    // absolutes, PROVIDE-defaulted symbols, weak fallbacks,
    // layout-derived `_*_start/_*_end` brackets, anything else base
    // ended up with at link time.
    let elf = object::File::parse(&*bytes)
        .with_context(|| format!("parse {} for symtab snapshot", path.display()))?;
    let tls = crate::combine::pt_tls(&bytes)?;
    let load_spans = crate::combine::pt_load_spans(&bytes)?;
    let mut by_name: HashMap<String, u64> = HashMap::new();
    let mut by_name_ambiguous: HashSet<String> = HashSet::new();
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
        // TLS values translate to template vaddrs — same address space
        // as the section table (mirrors build_section_table).
        let Some(addr) =
            crate::combine::symbol_vaddr(sym.kind(), sym.address(), tls.map(|t| t.vaddr))
        else {
            continue;
        };
        match by_name.entry(name.to_string()) {
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(addr);
            }
            std::collections::hash_map::Entry::Occupied(o) => {
                // Same address twice (an alias) is fine; a *different*
                // address means the name is ambiguous and channel 3
                // can't safely resolve it without a tu_id.
                if *o.get() != addr {
                    by_name_ambiguous.insert(name.to_string());
                }
            }
        }
    }
    // Drop ambiguous names from the resolvable map so a channel-3
    // lookup misses and produces the precise "ambiguous" diagnostic
    // rather than silently binding to a first-seen address.
    for n in &by_name_ambiguous {
        by_name.remove(n);
    }

    let e_machine = base_e_machine(&bytes)?;

    Ok(BaseMetadata {
        manifest,
        by_section,
        ambiguous_sections,
        unplaced_mutable,
        by_name,
        by_name_ambiguous,
        tls,
        load_spans,
        e_machine,
    })
}

pub(crate) struct Closure {
    /// Nodes we must include in the overlay link (their trans_hash did
    /// not match base's). Sections matching base by trans_hash are
    /// skipped at the closure-walk boundary; their content is reached
    /// via base addresses, encoded as SHN_ABS+addend at prune time.
    pub closure: Vec<NodeId>,
}

/// `trans_hash`es of every node backed by a non-content-addressable
/// section (mutable data / NOBITS / zero-size — nominal identity, see
/// `SectionInfo::content_addressable`). Prune must never resolve an
/// *ambiguous* one of these to a representative copy: byte-identical
/// mutable sections at distinct addresses are distinct variables, and
/// aliasing them is exactly the silent-stale-bind failure mode this
/// design exists to prevent.
fn mutable_trans_hashes(scan: &ScanResult) -> HashSet<TransHash> {
    let mut out = HashSet::new();
    for (nid, nm) in scan.graph.nodes.iter().enumerate() {
        let mutable = nm.segments.iter().any(|seg| {
            seg.range.is_none()
                && !scan.objects[seg.object as usize].sections[seg.section as usize]
                    .content_addressable()
        });
        if mutable {
            out.insert(scan.trans_hash[nid as usize]);
        }
    }
    out
}

/// Nodes backed by SHF_TLS sections — channel-1 UND emissions for these
/// must be STT_TLS (ld rejects TLS-def-vs-non-TLS-ref binds).
fn tls_node_ids(scan: &ScanResult) -> HashSet<NodeId> {
    let mut out = HashSet::new();
    for (nid, nm) in scan.graph.nodes.iter().enumerate() {
        let tls = nm.segments.iter().any(|seg| {
            scan.objects[seg.object as usize].sections[seg.section as usize].sh_flags
                & u64::from(object::elf::SHF_TLS)
                != 0
        });
        if tls {
            out.insert(nid as NodeId);
        }
    }
    out
}


/// Closure + walk-refusal fixpoint. Positional (channel-2) anchors into
/// base's relaxed sections need offset translation; where the walk
/// REFUSES (ambiguous fates, deleted bytes, unwalkable node), the only
/// sound alternative is re-emitting the target — legal for immutable
/// content (base code keeps calling base's copy), a hard error for
/// mutable content (re-emitting would fork the variable). Pulling a
/// node into the closure adds sections (and their relocs) to the
/// frontier, so iterate to a fixed point; by construction dispose then
/// never sees a refusal. Off-frontier ambiguity costs nothing: the
/// walk runs only for offsets an actual reloc queries.
fn compute_closure_fixpoint(
    scan: &ScanResult,
    base: &BaseMetadata,
    roots: &[NodeId],
    walker: Option<&crate::relax::walker::Walker<'_>>,
) -> Result<Closure> {
    let mut forced: HashSet<NodeId> = HashSet::new();
    loop {
        let closure = compute_closure(scan, base, roots, &forced)?;
        let Some(walker) = walker else { return Ok(closure) };

        let closure_set: HashSet<NodeId> = closure.closure.iter().copied().collect();
        // Physical sections the pruned objects will keep — their relocs
        // are exactly what prune will ask dispose about.
        let mut kept_secs: HashSet<(u32, u32)> = HashSet::new();
        for &nid in &closure.closure {
            for seg in &scan.graph.nodes[nid as usize].segments {
                kept_secs.insert((seg.object, seg.section));
            }
        }

        let mut pulled: Vec<NodeId> = Vec::new();
        for &(obj, sec) in &kept_secs {
            let Some(site_map) = scan.graph.reloc_targets.get(&(obj, sec)) else { continue };
            for r in &scan.objects[obj as usize].sections[sec as usize].relocs {
                let (tnid, value) = match site_map.get(&(r.offset, r.r_type)) {
                    Some(&crate::graph::ResolvedTarget::Symbol { nid, value }) => (nid, value),
                    Some(&crate::graph::ResolvedTarget::Section { nid }) => (nid, 0),
                    // External → channel 4 (output-space symtab
                    // address, no translation).
                    Some(&crate::graph::ResolvedTarget::External) | None => continue,
                };
                if closure_set.contains(&tnid) || forced.contains(&tnid) {
                    continue; // channel 1 — UND, no anchor
                }
                let th = scan.trans_hash[tnid as usize];
                if !base.by_section.contains_key(&th) {
                    continue; // channel 3 — dispose bails with its own message
                }
                if base.ambiguous_sections.contains(&th)
                    && r.target_section.is_none()
                    && base.by_name.contains_key(&r.target)
                {
                    continue; // channel 2a name pin — output-space, no translation
                }
                let q = i128::from(value) + i128::from(r.addend);
                if let Err(why) = walker.query(tnid, q) {
                    if node_content_addressable(tnid, scan) {
                        pulled.push(tnid);
                    } else {
                        let names: Vec<&str> = scan.graph.nodes[tnid as usize]
                            .defined_symbols
                            .iter()
                            .map(|s| s.name.as_str())
                            .collect();
                        bail!(
                            "reloc in obj {obj} section {sec} targets mutable node \
                             [{}] whose base placement the walk can't translate \
                             ({why}) — no sound resolution exists (re-emitting \
                             would fork the variable).",
                            names.join(", "),
                        );
                    }
                }
            }
        }
        if pulled.is_empty() {
            return Ok(closure);
        }
        pulled.sort_unstable();
        pulled.dedup();
        eprintln!(
            "graft overlay: lazy walk re-emitting {} target(s) it refused to translate",
            pulled.len()
        );
        forced.extend(pulled);
    }
}

fn compute_closure(
    scan: &ScanResult,
    base: &BaseMetadata,
    roots: &[NodeId],
    forced: &HashSet<NodeId>,
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

    // Literal pools always travel with the code that references them
    // (xtensa): `l32r` reaches −256KB backward only, so a re-emitted
    // function can't reach base's copy of its pool, while a re-emitted
    // pool has no range problem (pool words are absolute values, and
    // the script's wildcards keep pools adjacent to their code in
    // slack). Every node on the DFS stack was demanded by an Included
    // node (or is a root), so a *popped* pool node is referenced by
    // re-emitted code and must never be Provided.
    let pool_rule = base.e_machine == object::elf::EM_XTENSA;

    // DFS from every root. ld's gc-sections would start from the same
    // set; the Provided/Included classification terminates branches
    // whose trans_hash matches base (i.e., base's already-linked
    // version is interchangeable with whatever overlay would emit).
    // `forced` nodes (walk-refusal pulls from the fixpoint pre-pass)
    // are seeded and never Provided.
    let mut stack: Vec<NodeId> = roots.to_vec();
    stack.extend(forced.iter().copied());
    while let Some(nid) = stack.pop() {
        if decision[nid as usize] != Decision::Unknown {
            continue;
        }
        let force_pool = pool_rule && is_literal_pool(nid, scan);
        if !force_pool && !forced.contains(&nid) && classify_provided(nid, scan, base) {
            decision[nid as usize] = Decision::Provided;
        } else {
            if force_pool && !node_content_addressable(nid, scan) {
                let nm = &scan.graph.nodes[nid as usize];
                let names: Vec<&str> =
                    nm.defined_symbols.iter().map(|s| s.name.as_str()).collect();
                bail!(
                    "literal pool node {nid} [{}] is not content-addressable — \
                     re-emitting it alongside base's copy would fork mutable state",
                    names.join(", "),
                );
            }
            // Fork guard: this node is mutable, base PLACED it (its key
            // matched map records) but couldn't recover the address —
            // and precisely because the miss changed no hashes, base's
            // unchanged referrers still use base's copy. Re-emitting
            // would give changed referrers a second live copy of the
            // same variable. A genuinely new/changed mutable node is
            // NOT in this set (its hash matches no base-scan node) and
            // re-emits normally — the content change cascades every
            // reachable referrer into the closure with it.
            if base.unplaced_mutable.contains(&scan.trans_hash[nid as usize])
                && !node_content_addressable(nid, scan)
            {
                let nm = &scan.graph.nodes[nid as usize];
                let names: Vec<&str> =
                    nm.defined_symbols.iter().map(|s| s.name.as_str()).collect();
                bail!(
                    "mutable node {nid} [{}] is placed in base but its address could \
                     not be recovered (ambiguous map attribution at base link) — \
                     re-emitting it would fork its state between base's copy and the \
                     overlay's. Rebase, or fix the attribution collision.",
                    names.join(", "),
                );
            }
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

/// Pool predicate: any segment whose section name contains `.literal`
/// (the same convention `relax::xtensa::extract_input` keys on).
fn is_literal_pool(nid: NodeId, scan: &ScanResult) -> bool {
    scan.graph.nodes[nid as usize].segments.iter().any(|seg| {
        scan.objects[seg.object as usize].sections[seg.section as usize]
            .name
            .contains(".literal")
    })
}

/// Force-included nodes (pools, walk-refusal pulls) must be safe to
/// duplicate: base code keeps reading base's copy, so a writable
/// section would fork state.
fn node_content_addressable(nid: NodeId, scan: &ScanResult) -> bool {
    scan.graph.nodes[nid as usize].segments.iter().all(|seg| {
        scan.objects[seg.object as usize].sections[seg.section as usize].content_addressable()
    })
}

/// True iff base can satisfy this node positionally: its `trans_hash` is
/// in base's section table (a recovered, unambiguous address) or is a
/// known content-identical-but-multi-address section (resolved by name at
/// prune time). Otherwise the node must be Included — base either has no
/// copy (content differs) or graft couldn't recover its address.
/// Re-emitting is safe for content (interchangeable bytes) but NOT for
/// an unattributed mutable node — `compute_closure` refuses those via
/// `base.unplaced_mutable` (re-emission would fork the variable's state,
/// since an attribution miss cascades no referrers the way a content
/// change does). See `docs/worklogs/14-identity-granularity.md`.
fn classify_provided(nid: NodeId, scan: &ScanResult, base: &BaseMetadata) -> bool {
    let th = scan.trans_hash[nid as usize];
    let provided = base.by_section.contains_key(&th) || base.ambiguous_sections.contains(&th);
    if !provided
        && let Some(p) = crate::debug_flags::value("mismatch").ok().flatten()
        && !p.is_empty()
    {
        let nm = &scan.graph.nodes[nid as usize];
        let oh: String = th[..8].iter().map(|b| format!("{b:02x}")).collect();
        let names: Vec<&str> = nm.defined_symbols.iter().map(|s| s.name.as_str()).collect();
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
            .and_then(|mut f| {
                std::io::Write::write_all(
                    &mut f,
                    format!(
                        "node {nid} trans_hash={oh} (no base section) syms=[{}]\n",
                        names.join(", ")
                    )
                    .as_bytes(),
                )
            });
    }
    provided
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
    /// `(template vaddr, len)` of `GRAFT_TLS_SLACK` — the in-template
    /// hole re-emitted/new thread-locals land in. `None` when base has
    /// no TLS slack (no PT_TLS, or a pre-v6 base).
    pub tls: Option<(u64, u64)>,
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
    let mut tls: Option<(u64, u64)> = None;
    for sym in elf.symbols() {
        let Ok(name) = sym.name() else { continue };
        match name {
            "GRAFT_TEXT_SLACK" => text = Some((sym.address(), sym.size())),
            "GRAFT_RODATA_SLACK" => rodata = Some((sym.address(), sym.size())),
            "GRAFT_DATA_SLACK" => data = Some((sym.address(), sym.size())),
            // STT_TLS: address() is a template-relative offset;
            // translated to a template vaddr below.
            "GRAFT_TLS_SLACK" => tls = Some((sym.address(), sym.size())),
            _ => {}
        }
    }
    let tls = match tls {
        Some((off, len)) => crate::combine::pt_tls(base_bytes)?
            .map(|t| (t.vaddr + off, len)),
        None => None,
    };
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
        tls,
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

/// Names + sizes of base's `.debug_*` sections (sans
/// `.debug_gdb_scripts` — SHF_ALLOC, runtime-loaded, closure-managed).
/// Each size becomes the ADDRESS assigned to the same-named overlay
/// debug output section so ld resolves every cross-section DWARF
/// offset concatenation-correct (see `render_debug_stanzas`).
fn debug_section_bases(base_bytes: &[u8]) -> Result<Vec<(String, u64)>> {
    use object::{Object as _, ObjectSection as _};
    let elf =
        object::File::parse(base_bytes).context("parse base ELF for debug section sizes")?;
    Ok(elf
        .sections()
        .filter_map(|s| {
            let n = s.name().ok()?;
            (n.starts_with(".debug_") && n != ".debug_gdb_scripts")
                .then(|| (n.to_string(), s.size()))
        })
        .collect())
}

/// Output-section statements (SECTIONS-body context) implementing the
/// debug-merge address trick: each `.debug_X` output section is
/// assigned ADDRESS = size of base's `.debug_X`, non-alloc via
/// `(INFO)`. Every cross-section DWARF offset — strp into .debug_str,
/// DW_AT_stmt_list into .debug_line, abbrev_offset, DWARF5
/// str_offsets/addr bases — is populated by an ordinary relocation
/// resolved as `section address + addend`, so ld emits overlay debug
/// content whose offsets are already correct for a world where it sits
/// concatenated AFTER base's sections. Combine then does exactly that
/// concatenation (merge_debug_sections) — no DWARF is ever parsed.
/// Overlay-only debug sections base lacks have no stanza and
/// orphan-place non-alloc at 0 (self-consistent; combine skips them
/// with a note).
fn render_debug_stanzas(debug_bases: &[(String, u64)]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for (name, base_len) in debug_bases {
        let _ = writeln!(out, "  {name} {base_len:#x} (INFO) : {{ *({name}) }}");
    }
    out
}

fn setup_xtensa_layout(
    work_dir: &Path,
    base_bytes: &[u8],
    argv: &[String],
) -> Result<XtensaLayout> {
    let slack = compute_slack(base_bytes)?;
    let ram = compute_xtensa_ram_usage(base_bytes)?;
    let debug_stanzas = render_debug_stanzas(&debug_section_bases(base_bytes)?);
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

            let blockers = render_blockers_ld_esp_hal(&ram, &debug_stanzas);
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

            let blockers = render_blockers_ld_esp_idf(&ram, &debug_stanzas);
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
/// and `.dram0.dummy` (reserves the DRAM alias of IRAM usage —
/// esp32s3 IRAM/DRAM are two buses over one SRAM), and INCLUDE
/// `graft_blockers.ld` near the start so the IRAM blocker is parsed
/// before `.iram0.text`. The
/// `_flash_rodata_dummy_start = ABSOLUTE(ORIGIN(default_rodata_seg))`
/// ASSERT in memory.ld is gated on `_flash_rodata_dummy_start`
/// existing — replace the dummy clause with a stub that defines
/// the symbol at the slack origin.
///
/// Dropping `.dram0.dummy` is sound ONLY while the overlay emits no
/// IRAM content of its own: new IRAM bytes past base's usage would
/// alias base's live `.dram0.data` through the other bus. Until base
/// reserves an IRAM slack (with its DRAM alias kept free), a
/// trailing ASSERT pins that invariant — overlay IRAM content fails
/// the link loudly instead of silently corrupting base's data.
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

    // `.iram0.vectors` emits 0x400 of script-generated fill (absolute
    // `. = 0x180`-style bumps) even with zero input vector sections.
    // Loaded, those bytes would land past base's IRAM usage and alias
    // base's live `.dram0.data` through the other bus — NOLOAD keeps
    // the symbols (`_vector_table`, `_iram_start`) at their addresses
    // while emitting no bytes. Real vector-code edits are refused
    // graft-side (see the closure vector guard in `run`).
    let final_out = final_out.replacen(
        ".iram0.vectors :",
        ".iram0.vectors (NOLOAD) :",
        1,
    );
    if !final_out.contains(".iram0.vectors (NOLOAD) :") {
        bail!("sections.ld: no `.iram0.vectors :` clause — esp-idf layout changed?");
    }

    // Stub `.dram0.dummy`: overlay's dram0_0_seg IS the data slack — a
    // hole base already placed clear of every IRAM alias — so the
    // IRAM-mirror reservation must not eat it.
    let dummy_start = final_out
        .find(".dram0.dummy (NOLOAD):")
        .ok_or_else(|| anyhow!("sections.ld: no `.dram0.dummy` clause"))?;
    let body_open = final_out[dummy_start..]
        .find('{')
        .ok_or_else(|| anyhow!("sections.ld: malformed dram0.dummy (no `{{`)"))?;
    let body_close_rel = final_out[dummy_start + body_open..]
        .find('}')
        .ok_or_else(|| anyhow!("sections.ld: malformed dram0.dummy (no `}}`)"))?;
    let body_close = dummy_start + body_open + body_close_rel;
    let mut stubbed = String::with_capacity(final_out.len() + 128);
    stubbed.push_str(&final_out[..dummy_start + body_open + 1]);
    stubbed.push_str(
        "\n    /* graft overlay: IRAM-alias reservation removed; overlay's \
         dram0_0_seg is the data slack (already alias-free). */\n  ",
    );
    stubbed.push_str(&final_out[body_close..]);

    // The invariant that made the stub sound, enforced by ld itself:
    // the overlay may emit ZERO loadable IRAM content (its DRAM alias
    // past base's usage is base's live data).
    stubbed.push_str(
        "\nASSERT(SIZEOF(.iram0.text) == 0 && SIZEOF(.iram0.data) == 0 && \
         SIZEOF(.iram0.bss) == 0, \
         \"graft overlay: emits IRAM content — its DRAM alias would corrupt \
         base's data. Unsupported until base reserves an IRAM slack; keep \
         edited code out of IRAM (IRAM_ATTR) or rebuild base.\")\n",
    );
    Ok(stubbed)
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
fn render_blockers_ld_esp_hal(ram: &RamUsage, debug_stanzas: &str) -> String {
    format!(
        "/* graft overlay (esp-hal): reserve base's used IRAM bytes \
         so overlay's `.rwtext` lands at a fresh vaddr past base. \
         Debug stanzas: concatenation-addressed `.debug_*` — see \
         render_debug_stanzas. */\n\
         SECTIONS {{\n  \
         .graft_iram_blocker (NOLOAD) : {{\n    \
         . = . + {iram:#x};\n  \
         }} > iram_seg\n\
         {debug_stanzas}\
         }}\n",
        iram = ram.iram_blocker_bytes,
    )
}

/// esp-idf blocker: NOLOAD reservation in `iram0_0_seg`, INSERTed
/// BEFORE `.iram0.vectors` (the first section in iram0_0_seg in
/// esp-idf's sections.ld). Same effect as the esp-hal blocker — eat
/// base's used IRAM so overlay's IRAM clauses land past it.
fn render_blockers_ld_esp_idf(ram: &RamUsage, debug_stanzas: &str) -> String {
    // This file is INCLUDEd inside sections.ld's SECTIONS block
    // (mutate_sections_ld), so statements here are SECTIONS-body
    // context — no SECTIONS wrapper. The vendor script has no
    // `.debug_*` rules of its own, so the stanzas conflict with
    // nothing (base's debug sections were orphan-placed).
    format!(
        "/* graft overlay (esp-idf): reserve base's used IRAM bytes \
         so overlay's `.iram0.text` / `.iram0.vectors` etc. land at \
         fresh vaddrs past base. Debug stanzas: concatenation-addressed \
         `.debug_*` — see render_debug_stanzas. */\n\
         .graft_iram_blocker (NOLOAD) : {{\n  \
         . = . + {iram:#x};\n\
         }} > iram0_0_seg\n\
         {debug_stanzas}",
        iram = ram.iram_blocker_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal ELF with exactly-controlled section names, sh_flags and
    /// bytes, for exercising `check_overlay_sections`.
    fn fake_elf(sections: &[(&str, u64, &[u8])]) -> Vec<u8> {
        use object::write::Object as WObject;
        let mut obj = WObject::new(
            object::BinaryFormat::Elf,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        for (name, sh_flags, data) in sections {
            let id = obj.add_section(Vec::new(), name.as_bytes().to_vec(), object::SectionKind::Data);
            obj.section_mut(id).set_data(data.to_vec(), 1);
            obj.section_mut(id).flags = object::write::SectionFlags::Elf { sh_flags: *sh_flags };
        }
        obj.write().unwrap()
    }

    const ALLOC: u64 = object::elf::SHF_ALLOC as u64;

    #[test]
    fn audit_placed_sections_and_empty_audits_pass() {
        let base = fake_elf(&[(".text", ALLOC, b"\x90")]);
        let overlay = fake_elf(&[
            (".text", ALLOC, b"\x90"),
            (".got", ALLOC, b"\0\0\0\0\0\0\0\0"),
            (".graft.map.0", ALLOC, b""),
            (".graft.audit.note.gnu.property", 0, b""),
            (".graft.audit.initfini", 0, b""),
        ]);
        check_overlay_sections(&overlay, &base).unwrap();
    }

    #[test]
    fn audit_orphan_alloc_section_refuses() {
        let base = fake_elf(&[(".text", ALLOC, b"\x90")]);
        let overlay = fake_elf(&[(".note.mystery", ALLOC, b"\x01")]);
        let err = check_overlay_sections(&overlay, &base).unwrap_err().to_string();
        assert!(err.contains(".note.mystery") && err.contains("orphan"), "{err}");
    }

    #[test]
    fn audit_note_property_drift_refuses_and_equality_passes() {
        // Base lacks the note, overlay carries one → refuse.
        let base = fake_elf(&[(".text", ALLOC, b"\x90")]);
        let overlay =
            fake_elf(&[(".graft.audit.note.gnu.property", 0, b"\x04\0\0\0feat")]);
        let err = check_overlay_sections(&overlay, &base).unwrap_err().to_string();
        assert!(err.contains("note.gnu.property"), "{err}");
        // Byte-identical counterpart in base → pass.
        let base_eq = fake_elf(&[(".note.gnu.property", ALLOC, b"\x04\0\0\0feat")]);
        check_overlay_sections(&overlay, &base_eq).unwrap();
    }

    #[test]
    fn audit_initfini_content_refuses() {
        let base = fake_elf(&[(".text", ALLOC, b"\x90")]);
        let overlay = fake_elf(&[(".graft.audit.initfini", 0, b"\0\0\0\0\0\0\0\0")]);
        let err = check_overlay_sections(&overlay, &base).unwrap_err().to_string();
        assert!(err.contains("init_array"), "{err}");
    }

    #[test]
    fn resolved_libraries_keep_their_command_line_positions() {
        use crate::scan::ScanInput::*;
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.a");
        let middle = dir.path().join("libmiddle.a");
        std::fs::write(&middle, b"").unwrap();
        let args = crate::argv::parse(&["cc".into(), "main.o".into(),
            first.display().to_string(), format!("-L{}", dir.path().display()),
            "-Wl,--start-group,-lmiddle".into(), first.display().to_string(),
            "-Wl,--end-group".into()]);
        let resolved = resolve_scan_inputs(&args).unwrap();
        assert_eq!(resolved, vec![File("main.o".into()), File(first.clone()),
            StartGroup, File(middle), File(first), EndGroup]);
    }

    /// Build a scan over one synthesized object: changed `main`
    /// (`.text.main`, reloc → X) plus mutable static X (`.bss.X`,
    /// NOBITS). Returns (scan, main_nid, bss_nid).
    fn scan_main_referencing_bss() -> (crate::scan::ScanResult, u32, u32) {
        use object::write::{
            Object as WObject, Relocation as WRelocation, Symbol as WSymbol, SymbolSection,
        };
        let mut obj = WObject::new(
            object::BinaryFormat::Elf,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let bss = obj.add_section(Vec::new(), b".bss.X".to_vec(), object::SectionKind::UninitializedData);
        obj.section_mut(bss).append_bss(16, 4);
        let x = obj.add_symbol(WSymbol {
            name: b"X".to_vec(),
            value: 0,
            size: 16,
            kind: object::SymbolKind::Data,
            scope: object::write::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(bss),
            flags: object::write::SymbolFlags::None,
        });
        let text = obj.add_section(Vec::new(), b".text.main".to_vec(), object::SectionKind::Text);
        obj.section_mut(text).set_data(vec![0x8b, 0x05, 0, 0, 0, 0, 0xc3], 16);
        obj.add_symbol(WSymbol {
            name: b"main".to_vec(),
            value: 0,
            size: 7,
            kind: object::SymbolKind::Text,
            scope: object::write::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: object::write::SymbolFlags::None,
        });
        obj.add_relocation(
            text,
            WRelocation {
                offset: 2,
                symbol: x,
                addend: -4,
                flags: object::RelocationFlags::Elf { r_type: object::elf::R_X86_64_PC32 },
            },
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("main.o");
        std::fs::write(&path, obj.write().unwrap()).unwrap();
        let scan = crate::scan::run(
            &[path],
            &[] as &[std::path::PathBuf],
            &[],
            &[],
            None,
        )
        .unwrap();
        let (main_nid, _) = scan.graph.symbols.resolve_global("main").unwrap();
        let (bss_nid, _) = scan.graph.symbols.resolve_global("X").unwrap();
        (scan, main_nid, bss_nid)
    }

    fn minimal_base(unplaced_mutable: HashSet<TransHash>) -> BaseMetadata {
        BaseMetadata {
            manifest: metadata::GraftManifest {
                magic: metadata::GRAFT_MAGIC,
                version: SCHEMA_VERSION,
                hash_algo_version: metadata::HASH_ALGO_VERSION,
                base_abi: [0; 20],
                entry_symbol: "main".into(),
                toolchain_stamp: String::new(),
                overlay_region: (0, 0),
                boot: None,
                argv_flags: Vec::new(),
                script_hashes: Vec::new(),
            },
            by_section: HashMap::new(),
            ambiguous_sections: HashSet::new(),
            unplaced_mutable,
            by_name: HashMap::new(),
            by_name_ambiguous: HashSet::new(),
            tls: None,
            load_spans: Vec::new(),
            e_machine: object::elf::EM_X86_64,
        }
    }

    /// The fork guard: a mutable node base placed but couldn't
    /// attribute must refuse re-emission — the attribution miss
    /// cascades no referrer hashes, so base's unchanged referrers
    /// would keep base's copy while re-emitted referrers bound a
    /// fresh one.
    #[test]
    fn walk_refuses_unplaced_mutable_node() {
        let (scan, main_nid, bss_nid) = scan_main_referencing_bss();
        let base = minimal_base(HashSet::from([scan.trans_hash[bss_nid as usize]]));
        let err = match compute_closure(&scan, &base, &[main_nid], &HashSet::new()) {
            Ok(_) => panic!("unplaced mutable node must refuse re-emission"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("fork"), "unexpected error: {err}");
    }

    /// Control: the same mutable node NOT in the unplaced set (a
    /// genuinely new static — base has no copy) re-emits normally.
    #[test]
    fn walk_reemits_new_mutable_node() {
        let (scan, main_nid, bss_nid) = scan_main_referencing_bss();
        let base = minimal_base(HashSet::new());
        let closure = compute_closure(&scan, &base, &[main_nid], &HashSet::new()).unwrap();
        assert!(closure.closure.contains(&main_nid));
        assert!(closure.closure.contains(&bss_nid), "new static must re-emit");
    }

    /// Control: an unplaced-mutable hash that the walk never reaches
    /// (its referrer is Provided in base) must not refuse.
    #[test]
    fn unreached_unplaced_mutable_does_not_refuse() {
        let (scan, main_nid, bss_nid) = scan_main_referencing_bss();
        let mut base = minimal_base(HashSet::from([scan.trans_hash[bss_nid as usize]]));
        // main unchanged: its hash IS in base's table → Provided; the
        // walk stops there and never reaches X.
        base.by_section.insert(
            scan.trans_hash[main_nid as usize],
            metadata::Placed { addr: 0x1000, out_size: 7 },
        );
        let closure = compute_closure(&scan, &base, &[main_nid], &HashSet::new()).unwrap();
        assert!(closure.closure.is_empty(), "nothing changed → empty closure");
    }

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
            tls: None,
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
            tls: None,
        };
        assert!(mutate_memory_x(input, &slack).is_err());
    }

    #[test]
    fn blockers_carry_concatenation_addressed_debug_stanzas() {
        let ram = RamUsage { iram_blocker_bytes: 0x100 };
        let stanzas = render_debug_stanzas(&[
            (".debug_info".to_string(), 0x232def),
            (".debug_str".to_string(), 0x182cb8),
        ]);
        // esp-hal: blockers file is INCLUDEd at top level — stanzas
        // must sit inside its own SECTIONS wrapper.
        let hal = render_blockers_ld_esp_hal(&ram, &stanzas);
        assert!(hal.contains(".debug_info 0x232def (INFO) : { *(.debug_info) }"));
        assert!(hal.find("SECTIONS {").unwrap() < hal.find(".debug_info").unwrap());
        // esp-idf: blockers content is INCLUDEd inside sections.ld's
        // SECTIONS block — raw statements, no SECTIONS wrapper.
        let idf = render_blockers_ld_esp_idf(&ram, &stanzas);
        assert!(idf.contains(".debug_str 0x182cb8 (INFO) : { *(.debug_str) }"));
        assert!(!idf.contains("SECTIONS"));
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
