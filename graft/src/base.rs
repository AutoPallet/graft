//! Base mode: the first, from-scratch link.
//!
//! Pre-scan runs in a background thread while the real linker does its
//! work on the same inputs — hashing hides under the linker's runtime.
//! After the link lands, we re-open the output ELF for `.symtab`
//! addresses, join them with the pre-scan's trans_hashes, and attach
//! `.graft.manifest` + `.graft.symhash` as SHF_ALLOC=0 sections.

use std::io::Write;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, anyhow, bail};
use object::{Object, ObjectSymbol, SymbolScope};

use crate::argv;
use crate::elf::SymbolBind;
use crate::elf_attach::{self, NewSection};
use crate::metadata::{
    GRAFT_MAGIC, GraftManifest, SCHEMA_VERSION, SECTION_MANIFEST, SECTION_SYMHASH, SymHashEntry,
    encode_manifest, encode_symhash,
};
use crate::scan::{self, ScanResult};

pub fn link(argv: Vec<String>) -> ExitCode {
    match run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft base: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(argv: Vec<String>) -> Result<()> {
    // ldproxy (esp-idf-sys's link wrapper) can ask the real linker
    // to chdir before resolving relative archive paths via the
    // `--ldproxy-cwd <dir>` flag. Inputs in argv after that flag
    // (e.g. `esp-idf/xtensa/libxtensa.a`) are relative to that dir,
    // not to graft's cwd. Apply it here so both the pre-scan and
    // the linker invocation see the same view. ldproxy itself still
    // sees the flag in passthrough — chdir is idempotent.
    if let Some(cwd) = extract_flag(&argv, "--ldproxy-cwd") {
        std::env::set_current_dir(&cwd)
            .with_context(|| format!("chdir to --ldproxy-cwd {cwd}"))?;
    }

    let link_args = argv::parse(&argv);
    let output = link_args.output.clone().ok_or_else(|| anyhow!("no -o <path> in argv"))?;

    let t_start = std::time::Instant::now();

    // Spawn pre-scan concurrently with the real linker. Both touch the
    // same files (read-only), so there's no contention. Scan sees only
    // the user-supplied inputs — the synthetic slack `.o` (if any) is
    // pure linker-side machinery and shouldn't appear in the call graph.
    let driver = crate::argv::driver_path(&argv);
    let (eager_inputs, deferred_inputs) =
        crate::overlay::resolve_scan_inputs(&link_args, &driver);
    let extra_roots = link_args.undefined.clone();
    let wrapped = link_args.wrapped.clone();
    let scan_handle = std::thread::spawn(move || {
        let t = std::time::Instant::now();
        let r = scan::run(&eager_inputs, &deferred_inputs, &extra_roots, &wrapped);
        (r, t.elapsed())
    });

    // Splice mode needs base to carry slack regions. Detect the target
    // arch from the inputs to pick the right default mode (xtensa
    // defaults to splice; x86 hosted defaults to append). Inject only
    // when the resolved mode is Splice.
    let arch = crate::slack::detect_architecture(&link_args.inputs)
        .context("detect target architecture from input objects")?;
    let e_machine = e_machine_of(arch);
    let mode = crate::slack::Mode::resolve(e_machine)?;
    let argv = if mode == crate::slack::Mode::Splice {
        inject_slack(argv, arch, &output)?
    } else {
        argv
    };

    let t_link_start = std::time::Instant::now();
    let ld_status = exec_real_linker(&argv)?;
    let t_link = t_link_start.elapsed();
    let (scan_result, t_scan) = scan_handle
        .join()
        .map_err(|_| anyhow!("pre-scan thread panicked"))?;
    let scan_result = scan_result.context("pre-scan failed")?;

    let t_parallel = t_start.elapsed();

    if !ld_status.success() {
        bail!("real linker exited with {}", ld_status);
    }

    let t_post = std::time::Instant::now();
    let elf_bytes = std::fs::read(&output).with_context(|| format!("read {}", output.display()))?;
    if let Ok(p) = std::env::var("GRAFT_DEBUG_DUMP_GRAPH")
        && !p.is_empty()
    {
        if let Err(e) = crate::debug_dump::dump_graph(std::path::Path::new(&p), &scan_result) {
            eprintln!("graft base: GRAFT_DEBUG_DUMP_GRAPH write {p} failed: {e}");
        }
    }
    let entries = build_symhash(&scan_result, &elf_bytes)?;

    let manifest = GraftManifest {
        magic: GRAFT_MAGIC,
        version: SCHEMA_VERSION,
        base_abi: compute_base_abi(&elf_bytes),
        entry_symbol: find_entry_symbol(&elf_bytes).unwrap_or_else(|| "main".into()),
        toolchain_stamp: toolchain_stamp(),
        overlay_region: (0, 0), // M0.5 doesn't reserve one; overlay picks a disjoint addr
    };

    let manifest_bytes = encode_manifest(&manifest)?;
    let symhash_bytes = encode_symhash(&entries)?;
    let new_elf = elf_attach::append_sections(
        &elf_bytes,
        &[
            NewSection { name: SECTION_MANIFEST, data: &manifest_bytes },
            NewSection { name: SECTION_SYMHASH, data: &symhash_bytes },
        ],
    )?;

    atomic_write(&output, &new_elf)?;

    let t_total = t_start.elapsed();
    eprintln!(
        "graft base: {} objects · {} sections · {} symhash entries · \
         link {:.1?} · scan {:.1?} · link+scan {:.1?} · attach {:.1?} · total {:.1?}",
        scan_result.objects.len(),
        scan_result.graph.nodes.len(),
        entries.len(),
        t_link,
        t_scan,
        t_parallel,
        t_post.elapsed(),
        t_total,
    );
    Ok(())
}

/// Synthesize a slack `.o`, write it next to the output, and append
/// it (plus `--undefined=` flags so `--gc-sections` keeps it) to the
/// linker argv. Idempotent on re-link.
fn inject_slack(
    mut argv: Vec<String>,
    arch: object::Architecture,
    output: &std::path::Path,
) -> Result<Vec<String>> {
    let params = crate::slack::SlackParams::from_env();
    let bytes = crate::slack::synthesize(arch, &params)?;
    let slack_path = output.with_extension("graft-slack.o");
    atomic_write(&slack_path, &bytes)?;

    argv.push(slack_path.to_string_lossy().into_owned());
    argv.push(format!("-Wl,--undefined={}", crate::slack::TEXT_SYMBOL));
    argv.push(format!("-Wl,--undefined={}", crate::slack::RODATA_SYMBOL));
    argv.push(format!("-Wl,--undefined={}", crate::slack::DATA_SYMBOL));
    Ok(argv)
}

/// Map `object::Architecture` back to its ELF `e_machine` constant.
/// Used to pick mode defaults without re-reading the input files.
fn e_machine_of(arch: object::Architecture) -> u16 {
    use object::Architecture;
    use object::elf;
    match arch {
        Architecture::X86_64 => elf::EM_X86_64,
        Architecture::I386 => elf::EM_386,
        Architecture::Aarch64 => elf::EM_AARCH64,
        Architecture::Xtensa => elf::EM_XTENSA,
        _ => 0,
    }
}

fn exec_real_linker(argv: &[String]) -> Result<std::process::ExitStatus> {
    let real = std::env::var("GRAFT_REAL_LD").unwrap_or_else(|_| "cc".into());
    let status = Command::new(&real)
        .args(&argv[1..])
        .status()
        .with_context(|| format!("exec {real}"))?;
    Ok(status)
}

/// Join scan output (symbol → defining section → trans_hash) with the
/// output ELF's `.symtab` (symbol → address, size, bind). Each entry
/// stores `(symhash, address, size)` — the symhash folds the symbol's
/// stable name (where it has one) into the section's trans_hash, so
/// identity is content-keyed and immune to compiler-internal renaming.
/// See `hash::symhash_of`.
fn build_symhash(scan: &ScanResult, elf_bytes: &[u8]) -> Result<Vec<SymHashEntry>> {
    let elf = object::File::parse(elf_bytes).context("parse output ELF")?;

    // (symbol_name, tu_id_or_none) → (trans_hash, bind) of the defining
    // section. `bind` is tracked so we can match ld's resolution rule:
    // Global > Weak regardless of scan order. tu_id distinguishes
    // same-named locals across TUs.
    let mut sym_trans_hash: std::collections::HashMap<
        (String, Option<[u8; 8]>),
        ([u8; 16], SymbolBind),
    > = Default::default();
    for (obj_idx, obj) in scan.objects.iter().enumerate() {
        for sym in &obj.symbols {
            let Some(sec_idx) = sym.defining_section else { continue };
            let Some(nid) = node_id_of(&scan.graph, obj_idx as u32, sec_idx as u32) else {
                continue;
            };
            let th = scan.trans_hash[nid as usize];
            let key_tu = match sym.bind {
                SymbolBind::Global | SymbolBind::Weak => None,
                SymbolBind::Local => Some(obj.tu_id),
            };
            // ld's resolution rules:
            //   - Two Global defs of the same name → "multiple
            //     definition" link error. Mirror loudly.
            //   - Global > Weak: a later Global upgrades over an
            //     earlier Weak (and vice-versa: Weak doesn't downgrade
            //     a Global).
            //   - Multiple Weaks: first encountered wins (matches ld's
            //     left-to-right archive search).
            use std::collections::hash_map::Entry;
            match sym_trans_hash.entry((sym.name.clone(), key_tu)) {
                Entry::Vacant(v) => {
                    v.insert((th, sym.bind));
                }
                Entry::Occupied(mut o) => {
                    let (existing_th, existing_bind) = *o.get();
                    match (existing_bind, sym.bind) {
                        (SymbolBind::Global, SymbolBind::Global)
                            if existing_th != th =>
                        {
                            bail!(
                                "graft base: multiple Global definitions of {:?} with \
                                 differing trans_hashes — base.elf would not link cleanly",
                                sym.name,
                            );
                        }
                        (SymbolBind::Weak, SymbolBind::Global) => {
                            o.insert((th, sym.bind));
                        }
                        _ => {} // keep existing
                    }
                }
            }
        }
    }
    // Drop bind from the value type for the lookup-side use below.
    let mut sym_trans_hash: std::collections::HashMap<(String, Option<[u8; 8]>), [u8; 16]> =
        sym_trans_hash.into_iter().map(|(k, (th, _))| (k, th)).collect();
    // Aggregator nodes own bracket symbols (`__init_array_start`
    // etc.). Pass-2 walks base.elf's `.symtab` and finds these — they
    // exist there because the linker script defined them — so we need
    // an entry in `sym_trans_hash` keyed on the bracket name → the
    // aggregator's trans_hash.
    for (nid, nm) in scan.graph.nodes.iter().enumerate() {
        let th = scan.trans_hash[nid];
        for sym in &nm.defined_symbols {
            if sym.tu_id.is_some() { continue; } // not a bracket
            sym_trans_hash.insert((sym.name.clone(), None), th);
        }
    }

    // Walk output ELF's symtab; for each defined symbol we can pair
    // back to a trans_hash, emit (symhash, address, size). STT_FILE
    // markers partition STB_LOCAL ranges by source TU — track the
    // current TU's tu_id (blake3(stt_file_name)[:8]) to disambiguate
    // same-named locals.
    //
    // Critical: locals must round-trip through symhash. With LTO/fat,
    // every static (e.g. esp_println::LOCK) is STB_LOCAL — skipping
    // them makes overlay's classify see them as Included, overlay
    // re-allocates them at fresh addresses, base keeps using its own
    // copy, and the two halves of the program end up with different
    // views of every shared static.
    let mut entries: Vec<SymHashEntry> = Vec::new();
    let mut current_tu: Option<[u8; 8]> = None;
    let mut seen: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    for s in elf.symbols() {
        let name_raw = s.name().unwrap_or("");
        if matches!(s.kind(), object::SymbolKind::File) {
            current_tu = Some(tu_id_from_file_name(name_raw));
            continue;
        }
        if s.is_undefined() { continue; }
        if matches!(
            s.kind(),
            object::SymbolKind::Section | object::SymbolKind::Unknown
        ) {
            continue;
        }
        if name_raw.is_empty() { continue; }

        let is_global = matches!(s.scope(), SymbolScope::Linkage | SymbolScope::Dynamic);
        let key_tu = if is_global { None } else { current_tu };
        let Some(&th) = sym_trans_hash.get(&(name_raw.to_string(), key_tu)) else { continue };
        let symhash = crate::hash::symhash_of(crate::hash::stable_name_part(name_raw), &th);
        // Dedup: multiple symbols can collapse to the same symhash
        // (e.g. all anons with identical content). Keep the first;
        // every collapsed pair points at semantically interchangeable
        // bytes, so any of their addresses works.
        if !seen.insert(symhash) { continue; }
        entries.push(SymHashEntry {
            symhash,
            address: s.address(),
            size: s.size() as u32,
        });
    }
    entries.sort_by(|a, b| a.symhash.cmp(&b.symhash));
    Ok(entries)
}

/// Same derivation as `elf::ParsedObject::tu_id` — blake3(file)[:8].
fn tu_id_from_file_name(name: &str) -> [u8; 8] {
    let digest = *blake3::hash(name.as_bytes()).as_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

pub(crate) fn node_id_of(graph: &crate::graph::Graph, object: u32, section: u32) -> Option<u32> {
    // graph.nodes was built by a nested loop over (obj, sec), pushing
    // NodeId sequentially — so for every object we can compute the base
    // NodeId as the sum of section counts in prior objects.
    // O(1) lookup: scan once, build a prefix table. Small graphs, not a
    // bottleneck, so linear scan is fine.
    let mut target: Option<u32> = None;
    for (nid, nm) in graph.nodes.iter().enumerate() {
        if nm.segments.iter().any(|s| s.object == object && s.section == section) {
            target = Some(nid as u32);
            break;
        }
    }
    target
}

fn compute_base_abi(elf_bytes: &[u8]) -> [u8; 20] {
    // Prefer NT_GNU_BUILD_ID if present; otherwise fall back to
    // blake3(output ELF bytes) truncated to 20 bytes. Either is
    // sufficient for the "your overlay was built against a different
    // base" check M0.5 needs.
    if let Some(bid) = read_build_id(elf_bytes) {
        let mut out = [0u8; 20];
        let n = bid.len().min(20);
        out[..n].copy_from_slice(&bid[..n]);
        return out;
    }
    let digest = *blake3::hash(elf_bytes).as_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

fn read_build_id(elf_bytes: &[u8]) -> Option<Vec<u8>> {
    let elf = object::File::parse(elf_bytes).ok()?;
    elf.build_id().ok().flatten().map(|b| b.to_vec())
}

fn find_entry_symbol(elf_bytes: &[u8]) -> Option<String> {
    // `GRAFT_ENTRY_SYMBOL` overrides for debugging — moves the single
    // trampoline off `main` to a function the user controls, so they
    // can run code (printlns, memory probes) before the trampoline
    // fires and bisect crashes.
    if let Ok(s) = std::env::var("GRAFT_ENTRY_SYMBOL")
        && !s.is_empty()
    {
        return Some(s);
    }
    let _ = elf_bytes;
    Some("main".into())
}

fn toolchain_stamp() -> String {
    Command::new("rustc")
        .arg("-Vv")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.lines().find_map(|l| l.strip_prefix("commit-hash: ")).unwrap_or("?").to_string())
        .unwrap_or_else(|| "?".into())
}

/// Find `--flag value` or `--flag=value` in argv; return value if present.
pub(crate) fn extract_flag(argv: &[String], flag: &str) -> Option<String> {
    let prefix_eq = format!("{flag}=");
    let mut iter = argv.iter();
    while let Some(a) = iter.next() {
        if a == flag {
            return iter.next().cloned();
        }
        if let Some(v) = a.strip_prefix(&prefix_eq) {
            return Some(v.to_string());
        }
    }
    None
}

fn atomic_write(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("graft-tmp");
    {
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    // Preserve executable bit from the original (rustc linked it
    // executable; std::fs::rename doesn't copy perms for newly-created
    // files).
    if let Ok(orig_meta) = std::fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = orig_meta.permissions().mode();
        let mut p = std::fs::metadata(&tmp)?.permissions();
        p.set_mode(mode);
        std::fs::set_permissions(&tmp, p)?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

