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

    let link_args = argv::parse(&argv);
    let output = link_args
        .output
        .clone()
        .ok_or_else(|| anyhow!("no -o <path> in argv"))?;

    let base_path: PathBuf = std::env::var("GRAFT_BASE_ELF")
        .map(PathBuf::from)
        .map_err(|_| anyhow!("GRAFT_BASE_ELF not set"))?;
    let base = load_base_metadata(&base_path)?;

    let scan_inputs: Vec<PathBuf> = link_args.inputs.clone();
    let scan = scan::run(&scan_inputs).context("overlay pre-scan")?;

    let roots = roots::find_roots(&scan, &base, &link_args)?;
    let closure = compute_closure(&scan, &base, &roots)?;

    // Scratch dir next to the output path. Cleaned and recreated each
    // run so stale pruned .o's from a prior invocation don't confuse
    // the real linker.
    let work_dir = work_dir_for(&output);
    if work_dir.exists() {
        let _ = std::fs::remove_dir_all(&work_dir);
    }
    std::fs::create_dir_all(&work_dir)
        .with_context(|| format!("create {}", work_dir.display()))?;

    // Prune each source object; collect the pruned-.o paths.
    let pruned = prune_all(&scan, &closure, &work_dir)?;
    let renamed_total: usize = pruned.iter().map(|p| p.renamed_locals).sum();
    let kept_sec_total: usize = pruned.iter().map(|p| p.kept_sections).sum();

    // Write base_symbols.ld.
    let ld_script = work_dir.join("base_symbols.ld");
    write_base_symbols_ld(&closure, &ld_script)?;

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

    // Extend base_symbols.ld with PROVIDEs for *every* symbol in base's
    // .symtab. The closure walk only gives us ones we saw reloc-targeted,
    // but overlay's link (with `--no-undefined`-like semantics) will
    // want every weak-personality ref, unwind table, libc internal
    // resolvable. Reading base.elf's symtab directly is authoritative
    // — it includes symbols from static libraries (`libunwind.a`,
    // `libc.a`) that scan never saw because they come through `-l`
    // rather than as `.o` / `.rlib` inputs.
    let all_base_syms_script = work_dir.join("base_addresses.ld");
    write_all_base_symbols_ld(&base_path, &all_base_syms_script)?;

    let overlay_elf = work_dir.join("overlay.elf");
    if pruned.is_empty() {
        write_empty_relocatable_for(&overlay_elf, e_machine)?;
    } else {
        let ld_status = run_real_linker(
            &pruned,
            &ld_script,
            &all_base_syms_script,
            &layout_script,
            &overlay_elf,
            xtensa_layout.as_ref(),
            &argv,
            base.manifest.entry_symbol.as_str(),
        )?;
        if !ld_status.success() {
            bail!(
                "real linker exited with {ld_status} (see {})",
                work_dir.display()
            );
        }
    }

    // Single-ELF output: combine base + overlay directly into cargo's
    // `-o` path. The standalone overlay.elf stays in work_dir for
    // debugging / inspection, but cargo + everything downstream sees one
    // self-contained executable. The `graft combine` subcommand still
    // exists for explicit invocation against arbitrary base/overlay
    // pairs (snapshots, archived overlays, …), but no longer required
    // for the normal build loop.
    let combine_stats = crate::combine::combine(&base_path, &overlay_elf, &output)
        .with_context(|| {
            format!(
                "combine base={} overlay={} -> {}",
                base_path.display(),
                overlay_elf.display(),
                output.display()
            )
        })?;

    // Sidecar with the combine stats so callers (tests, dev driver) can
    // see the trampoline count etc. without parsing the linker's stderr
    // — rustc captures+filters linker stderr so eprintln won't reach
    // them. JSON-on-disk next to overlay.elf in work_dir.
    let stats_path = work_dir.join("combine-stats.json");
    write_combine_stats(&stats_path, &combine_stats)?;

    let summary = format!(
        "graft overlay: base {} symhash · overlay {} objs / {} sections · \
         closure {} sections · provides {} globals / {} locals · \
         pruned {} objs / {} sections / {} renamed-locals · \
         combined {} bytes (overlay payload {} @ {:#x}, {} trampolines) · \
         total {:.1?}\n\
         overlay.elf: {}\n",
        base.symhash_by_name.len(),
        scan.objects.len(),
        scan.graph.nodes.len(),
        closure.closure.len(),
        closure.provide_globals.len(),
        closure.provide_locals.len(),
        pruned.len(),
        kept_sec_total,
        renamed_total,
        combine_stats.combined_size,
        combine_stats.overlay_load_size,
        combine_stats.overlay_vaddr,
        combine_stats.trampolines.len(),
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

fn work_dir_for(output: &Path) -> PathBuf {
    // `target/debug/app` → `target/debug/app.graft-work`
    let mut p = output.as_os_str().to_os_string();
    p.push(".graft-work");
    PathBuf::from(p)
}

struct PrunedEntry {
    path: PathBuf,
    kept_sections: usize,
    renamed_locals: usize,
}

fn prune_all(scan: &ScanResult, closure: &Closure, work_dir: &Path) -> Result<Vec<PrunedEntry>> {
    // Group closure sections by object.
    let mut by_obj: HashMap<u32, HashSet<u32>> = HashMap::new();
    for &nid in &closure.closure {
        let nm = &scan.graph.nodes[nid as usize];
        by_obj.entry(nm.object).or_default().insert(nm.section);
    }

    let mut out: Vec<PrunedEntry> = Vec::new();
    for (obj_idx, keep_set) in by_obj {
        let input = &scan.inputs[obj_idx as usize];
        let parsed = &scan.objects[obj_idx as usize];
        let p = prune::prune_object(&input.bytes, parsed.tu_id, &keep_set)
            .with_context(|| format!("prune {}", input.label()))?;
        // Derive a stable filename — rcgu-object basename, flattened.
        let stem = input
            .member_name
            .as_deref()
            .map(|n| n.replace('/', "_"))
            .unwrap_or_else(|| {
                input
                    .source_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("obj")
                    .to_string()
            });
        let filename = format!("{obj_idx:04}_{stem}");
        let path = work_dir.join(&filename);
        std::fs::write(&path, &p.bytes)
            .with_context(|| format!("write {}", path.display()))?;
        out.push(PrunedEntry {
            path,
            kept_sections: p.kept_sections,
            renamed_locals: p.renamed_locals,
        });
    }
    // Sort for deterministic linker invocation order.
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn write_base_symbols_ld(closure: &Closure, path: &Path) -> Result<()> {
    use std::fmt::Write;
    let mut s = String::new();
    writeln!(s, "/* Generated by graft overlay: PROVIDEs base addresses for overlay's UND refs. */").unwrap();
    for (name, addr, _) in &closure.provide_globals {
        writeln!(s, "PROVIDE({name} = {addr:#x});").unwrap();
    }
    for (name, tu, addr, _) in &closure.provide_locals {
        let tu_hex: String = tu.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(s, "PROVIDE(\"{name}@{tu_hex}\" = {addr:#x});").unwrap();
    }
    std::fs::write(path, s).with_context(|| format!("write {}", path.display()))?;
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

fn write_all_base_symbols_ld(base_path: &Path, path: &Path) -> Result<()> {
    use object::{Object, ObjectSymbol};
    use std::fmt::Write;

    let bytes = std::fs::read(base_path)
        .with_context(|| format!("read {}", base_path.display()))?;
    let elf = object::File::parse(&*bytes).context("parse base ELF")?;

    let mut s = String::new();
    writeln!(s, "/* Every base-defined symbol as a PROVIDE: overlay's link resolves */\n\
                 /* UND references against these constants. Generated by graft overlay. */").unwrap();

    // Deduplicate by name — base occasionally has duplicate local-scope
    // entries with the same name across TUs; for PROVIDE purposes the
    // first address is sufficient (ld will warn on repeats).
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for sym in elf.symbols() {
        if sym.is_undefined() {
            continue;
        }
        let name = match sym.name() {
            Ok(n) if !n.is_empty() => n,
            _ => continue,
        };
        if !seen.insert(name.to_string()) {
            continue;
        }
        writeln!(s, "PROVIDE(\"{name}\" = {:#x});", sym.address()).unwrap();
    }
    std::fs::write(path, s).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn run_real_linker(
    pruned: &[PrunedEntry],
    base_symbols: &Path,
    all_base_symbols: &Path,
    layout: &Path,
    output: &Path,
    xtensa: Option<&XtensaLayout>,
    rustc_argv: &[String],
    entry_symbol: &str,
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

    // Our scripts MUST come before any of rustc's `-T` (notably
    // linkall.x): hal-defaults.x has `PROVIDE(__post_init =
    // no_init_hook)` which references a symbol undefined in
    // overlay's pruned input. Our base_addresses.ld defines
    // __post_init at base's address first, so linkall.x's PROVIDE
    // is suppressed.
    cmd.arg("-T").arg(base_symbols);
    cmd.arg("-T").arg(all_base_symbols);

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

    // Now forward rustc's link args verbatim (sans inputs and `-o`).
    for a in crate::argv::forwarded_link_args(rustc_argv) {
        cmd.arg(a);
    }

    // Pruned closure inputs replace rustc's original inputs.
    for p in pruned {
        cmd.arg(&p.path);
    }
    let status = cmd.status().with_context(|| format!("exec {real}"))?;
    Ok(status)
}

pub struct BaseMetadata {
    pub manifest: GraftManifest,
    /// `name` → entry. One per globally-visible symbol live in base's .symtab.
    pub symhash_by_name: HashMap<String, SymHashEntry>,
    /// `(name, tu_id)` → entry. For STB_LOCAL entries.
    pub symhash_by_local: HashMap<(String, [u8; 8]), SymHashEntry>,
}

fn load_base_metadata(path: &std::path::Path) -> Result<BaseMetadata> {
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
    let mut by_name: HashMap<String, SymHashEntry> = HashMap::with_capacity(entries.len());
    let mut by_local: HashMap<(String, [u8; 8]), SymHashEntry> = HashMap::new();
    for e in entries {
        match e.tu {
            None => {
                by_name.insert(e.name.clone(), e);
            }
            Some(tu) => {
                by_local.insert((e.name.clone(), tu), e);
            }
        }
    }
    Ok(BaseMetadata {
        manifest,
        symhash_by_name: by_name,
        symhash_by_local: by_local,
    })
}

pub(crate) struct Closure {
    /// Nodes we must include in the overlay link (their trans_hash did
    /// not match base's).
    pub closure: Vec<NodeId>,
    /// Defined globals we can satisfy from base — `(name, address, size)`.
    /// Emitted as `PROVIDE(name = 0x…);` in base_symbols.ld.
    pub provide_globals: Vec<(String, u64, u32)>,
    /// Defined locals we need to satisfy from base, renamed to
    /// `<name>@<tu_id>` when pruning.
    pub provide_locals: Vec<(String, [u8; 8], u64, u32)>,
}

fn compute_closure(
    scan: &ScanResult,
    base: &BaseMetadata,
    roots: &[NodeId],
) -> Result<Closure> {
    let mut closure: Vec<NodeId> = Vec::new();
    let mut provide_globals: Vec<(String, u64, u32)> = Vec::new();
    let mut provide_locals: Vec<(String, [u8; 8], u64, u32)> = Vec::new();

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
        match classify(nid, scan, base) {
            Classification::Provided { globals, locals } => {
                decision[nid as usize] = Decision::Provided;
                provide_globals.extend(globals);
                provide_locals.extend(locals);
            }
            Classification::Included => {
                decision[nid as usize] = Decision::Included;
                closure.push(nid);
                // Walk forward reloc targets. Any already-classified
                // node is a cache hit; Unknown nodes go back on the
                // stack.
                for &succ in &scan.graph.edges[nid as usize] {
                    if decision[succ as usize] == Decision::Unknown {
                        stack.push(succ);
                    }
                }
            }
        }
    }

    // Sort + dedup provides so the ld script is stable.
    provide_globals.sort();
    provide_globals.dedup_by(|a, b| a.0 == b.0);
    provide_locals.sort();
    provide_locals.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    // And closure for determinism.
    closure.sort();

    Ok(Closure {
        closure,
        provide_globals,
        provide_locals,
    })
}

enum Classification {
    Provided {
        globals: Vec<(String, u64, u32)>,
        locals: Vec<(String, [u8; 8], u64, u32)>,
    },
    Included,
}

/// Decide whether a section is Provided by base (any defined symbol in it
/// matches base.symhash on trans_hash) or Included in overlay's link.
fn classify(nid: NodeId, scan: &ScanResult, base: &BaseMetadata) -> Classification {
    let nm = &scan.graph.nodes[nid as usize];
    let obj = &scan.objects[nm.object as usize];
    let sec = &obj.sections[nm.section as usize];
    let th: TransHash = scan.trans_hash[nid as usize];

    // Collect defined symbols in this section.
    let mut globals: Vec<(String, u64, u32)> = Vec::new();
    let mut locals: Vec<(String, [u8; 8], u64, u32)> = Vec::new();
    let mut any_match = false;
    let mut any_defined_symbol = false;

    for &sym_idx in &sec.defined_symbols {
        let sym = &obj.symbols[sym_idx];
        if sym.name.is_empty() {
            continue;
        }
        any_defined_symbol = true;
        match sym.bind {
            SymbolBind::Global | SymbolBind::Weak => {
                if let Some(e) = base.symhash_by_name.get(&sym.name) {
                    if e.trans_hash == th {
                        any_match = true;
                        globals.push((sym.name.clone(), e.address, e.size));
                    }
                }
            }
            SymbolBind::Local => {
                if let Some(e) = base.symhash_by_local.get(&(sym.name.clone(), obj.tu_id)) {
                    if e.trans_hash == th {
                        any_match = true;
                        locals.push((sym.name.clone(), obj.tu_id, e.address, e.size));
                    }
                }
            }
        }
    }

    // A section with no defined symbols we can match can't be Provided —
    // we have no address to point at. (Examples: `.eh_frame` fragments,
    // `.rodata..Lanon.*` constants with no exported name.) Include it.
    if !any_defined_symbol || !any_match {
        return Classification::Included;
    }
    Classification::Provided { globals, locals }
}

fn format_closure_dump(scan: &ScanResult, c: &Closure) -> Vec<u8> {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "closure sections ({}):", c.closure.len());
    for &nid in &c.closure {
        let nm = &scan.graph.nodes[nid as usize];
        let obj = &scan.objects[nm.object as usize];
        let sec = &obj.sections[nm.section as usize];
        let label = scan.inputs[nm.object as usize].label();
        let _ = writeln!(s, "  [{nid}] {label} :: {} ({} bytes)", sec.name, sec.bytes.len());
    }
    let _ = writeln!(s, "provides globals ({}):", c.provide_globals.len());
    for (n, addr, sz) in &c.provide_globals {
        let _ = writeln!(s, "  {n} = {addr:#x} ({sz} bytes)");
    }
    let _ = writeln!(s, "provides locals ({}):", c.provide_locals.len());
    for (n, tu, addr, sz) in &c.provide_locals {
        let tu_hex: String = tu.iter().map(|b| format!("{b:02x}")).collect();
        let _ = writeln!(s, "  {n}@{tu_hex} = {addr:#x} ({sz} bytes)");
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
    for sym in elf.symbols() {
        let Ok(name) = sym.name() else { continue };
        match name {
            "GRAFT_TEXT_SLACK" => text = Some((sym.address(), sym.size())),
            "GRAFT_RODATA_SLACK" => rodata = Some((sym.address(), sym.size())),
            _ => {}
        }
    }
    let (text_start, text_len) = text.ok_or_else(|| {
        anyhow!(
            "base ELF: GRAFT_TEXT_SLACK symbol not found \
             (fixture must declare a #[link_section = \".text.graft_slack\"] static)"
        )
    })?;
    let (rodata_start, rodata_len) = rodata.ok_or_else(|| {
        anyhow!(
            "base ELF: GRAFT_RODATA_SLACK symbol not found \
             (fixture must declare a #[link_section = \".rodata.graft_slack\"] static)"
        )
    })?;
    if text_start & 3 != 0 || rodata_start & 3 != 0 {
        bail!(
            "GRAFT_*_SLACK must be 4-byte aligned — got irom={text_start:#x}, drom={rodata_start:#x}"
        );
    }
    Ok(Slack {
        text_start,
        text_len,
        rodata_start,
        rodata_len,
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

/// Find esp-hal's `memory.x` and `esp32s3.x` by scanning argv's `-L`
/// paths. Returns the resolved paths plus the full list of `-L`
/// directories so the caller can preserve them (we'll prepend
/// `work_dir` then add these for fallthrough).
fn find_memory_x_and_paths(argv: &[String]) -> Result<(PathBuf, PathBuf, Vec<PathBuf>)> {
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
    let mut memory_x: Option<PathBuf> = None;
    let mut esp32s3_x: Option<PathBuf> = None;
    for p in &paths {
        if memory_x.is_none() {
            let c = p.join("memory.x");
            if c.exists() {
                memory_x = Some(c);
            }
        }
        if esp32s3_x.is_none() {
            let c = p.join("esp32s3.x");
            if c.exists() {
                esp32s3_x = Some(c);
            }
        }
    }
    let memory_x = memory_x
        .ok_or_else(|| anyhow!("memory.x not found in any -L path ({} searched)", paths.len()))?;
    let esp32s3_x = esp32s3_x
        .ok_or_else(|| anyhow!("esp32s3.x not found in any -L path ({} searched)", paths.len()))?;
    Ok((memory_x, esp32s3_x, paths))
}

fn setup_xtensa_layout(
    work_dir: &Path,
    base_bytes: &[u8],
    argv: &[String],
) -> Result<XtensaLayout> {
    let slack = compute_slack(base_bytes)?;
    let ram = compute_xtensa_ram_usage(base_bytes)?;
    let (memory_x, esp32s3_x, search_paths) = find_memory_x_and_paths(argv)?;

    let memory_orig = std::fs::read_to_string(&memory_x)
        .with_context(|| format!("read {}", memory_x.display()))?;
    let memory_mutated = mutate_memory_x(&memory_orig, &slack)?;
    std::fs::write(work_dir.join("memory.x"), memory_mutated)
        .with_context(|| format!("write {}/memory.x", work_dir.display()))?;

    let esp_orig = std::fs::read_to_string(&esp32s3_x)
        .with_context(|| format!("read {}", esp32s3_x.display()))?;
    let esp_mutated = mutate_esp32s3_x(&esp_orig)?;
    std::fs::write(work_dir.join("esp32s3.x"), esp_mutated)
        .with_context(|| format!("write {}/esp32s3.x", work_dir.display()))?;

    let blockers = render_blockers_ld(&ram);
    std::fs::write(work_dir.join("graft_blockers.ld"), blockers)
        .with_context(|| format!("write {}/graft_blockers.ld", work_dir.display()))?;

    Ok(XtensaLayout {
        work_dir: work_dir.to_path_buf(),
        search_paths,
        slack,
    })
}

/// ESP32-S3 IRAM region, per esp-hal `memory.x`:
/// `0x4037_0000 .. 0x4040_0000`. Used to bucket base PT_LOADs.
const ESP32S3_IRAM_RANGE: (u64, u64) = (0x40370000, 0x40400000);
/// ESP32-S3 DRAM region: `0x3FC8_8000 .. 0x3FCF_0000`.
const ESP32S3_DRAM_RANGE: (u64, u64) = (0x3FC88000, 0x3FCF0000);

/// Bytes already used by base in IRAM. Counted from `iram_seg`'s
/// lowest base PT_LOAD start to its highest end. Drives the size of
/// the NOLOAD blocker so overlay's `.rwtext` is placed past base's
/// IRAM usage. DRAM doesn't get a blocker — base fully consumes
/// `dram_seg` (`.stack` extends to `ORIGIN(RWDATA)+LENGTH(RWDATA)`),
/// so we redirect overlay's `RWDATA` REGION_ALIAS to `dram2_seg`
/// instead (see `mutate_alias_x`).
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

/// Emit a NOLOAD reservation that eats the first `iram_blocker_bytes`
/// of `iram_seg`. Placement comes from the `> iram_seg` clause;
/// ordering relative to esp-hal's `.rwtext` is handled by
/// `mutate_esp32s3_x` INCLUDEing this script *before* the SECTIONS
/// block that pulls in `rwtext.x`, so ld lays out the blocker first.
/// (DRAM is handled by `mutate_alias_x` redirecting RWDATA →
/// `dram2_seg`; no blocker needed there.)
fn render_blockers_ld(ram: &RamUsage) -> String {
    format!(
        "/* graft overlay: reserve base's already-used IRAM bytes so \
         overlay's `.rwtext` lands at a fresh vaddr past base. */\n\
         SECTIONS {{\n  \
         .graft_iram_blocker (NOLOAD) : {{\n    \
         . = . + {iram:#x};\n  \
         }} > iram_seg\n\
         }}\n",
        iram = ram.iram_blocker_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutate_memory_x_replaces_two_lines() {
        let input = "\
RESERVE_ICACHE = 0x8000;
MEMORY
{
  vectors_seg ( RX )     : ORIGIN = 0x40378000, len = 0x400
  irom_seg ( RX )        : ORIGIN = 0x42000020, len = 32M - 0x20
  drom_seg ( R )         : ORIGIN = 0x3C000020, len = 32M - 0x20
  rtc_fast_seg(RWX) : ORIGIN = 0x600fe000, len = 8k
}
";
        let slack = Slack {
            text_start: 0x4201_7000,
            text_len: 0x10000,
            rodata_start: 0x3C00_2000,
            rodata_len: 0x10000,
        };
        let out = mutate_memory_x(input, &slack).unwrap();
        assert!(out.contains("irom_seg ( RX ) : ORIGIN = 0x42017000"));
        assert!(out.contains("drom_seg ( R ) : ORIGIN = 0x3c002000"));
        // Other lines preserved.
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
