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
    let layout_script = work_dir.join("overlay_layout.ld");
    write_overlay_layout_ld(&layout_script, OVERLAY_BASE_ADDR)?;

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
        write_empty_relocatable(&overlay_elf)?;
    } else {
        let ld_status = run_real_linker(
            &pruned,
            &ld_script,
            &all_base_syms_script,
            &layout_script,
            &overlay_elf,
        )?;
        if !ld_status.success() {
            bail!(
                "real linker exited with {ld_status} (see {})",
                work_dir.display()
            );
        }
    }

    // Write a stub to cargo's `-o` path so cargo sees success. `graft
    // combine` (M0.5.e) merges base.elf + overlay.elf → final artifact.
    std::fs::write(&output, b"graft-overlay-stub\n")
        .with_context(|| format!("write stub {}", output.display()))?;

    let summary = format!(
        "graft overlay: base {} symhash · overlay {} objs / {} sections · \
         closure {} sections · provides {} globals / {} locals · \
         pruned {} objs / {} sections / {} renamed-locals · total {:.1?}\n\
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

fn write_empty_relocatable(path: &Path) -> Result<()> {
    use object::{Architecture, BinaryFormat, Endianness, write::Object as WObject};
    let out = WObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let bytes = out.write().map_err(|e| anyhow!("write empty ET_REL: {e}"))?;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Fixed virtual address where overlay's output sections land. Must sit
/// within `call rel32` reach (±2 GB) of base's address range — base is
/// around 0x400000 on non-PIE x86-64 static, so 256 MB is plenty of gap
/// while staying within reach.
const OVERLAY_BASE_ADDR: u64 = 0x1000_0000;

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
) -> Result<std::process::ExitStatus> {
    let real = std::env::var("GRAFT_REAL_LD").unwrap_or_else(|_| "ld".into());
    let mut cmd = Command::new(&real);
    // Full link. `-nostdlib -static --no-dynamic-linker` prevents ld
    // from pulling crt*.o / libc / libunwind — every such symbol must
    // be resolved by base_addresses.ld. `--entry=0` because overlay
    // isn't a standalone executable (combine copies base's e_entry).
    cmd.arg("-o").arg(output);
    cmd.arg("-nostdlib");
    cmd.arg("-static");
    cmd.arg("--no-dynamic-linker");
    cmd.arg("--entry=0");
    // `--no-relax` stops ld from trying to shrink GOTPCREL → PC-rel
    // against an absolute PROVIDE (errors with "failed to convert
    // GOTPCREL relocation"; the relaxation assumes the target's
    // section is known, and our PROVIDEs are bare addresses).
    cmd.arg("--no-relax");
    cmd.arg("-T").arg(layout);
    cmd.arg("-T").arg(base_symbols);
    cmd.arg("-T").arg(all_base_symbols);
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
