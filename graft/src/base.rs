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
    let scan_handle = std::thread::spawn(move || {
        let t = std::time::Instant::now();
        let r = scan::run(&eager_inputs, &deferred_inputs, &extra_roots);
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
/// output ELF's `.symtab` (symbol → address, size, bind). Only symbols
/// present in both are emitted.
fn build_symhash(scan: &ScanResult, elf_bytes: &[u8]) -> Result<Vec<SymHashEntry>> {
    let elf = object::File::parse(elf_bytes).context("parse output ELF")?;

    // Build: section-node-id → (tu_id, trans_hash) for every defined symbol
    // in our scan. Keyed by symbol name; globals ignore tu_id.
    // We walk the scan's parsed objects to find each symbol's defining
    // section's NodeId (which we can look up via the symbol index).
    let mut global_hash: std::collections::HashMap<String, [u8; 16]> = Default::default();
    let mut local_hash: std::collections::HashMap<(String, [u8; 8]), [u8; 16]> = Default::default();

    for (obj_idx, obj) in scan.objects.iter().enumerate() {
        for sym in &obj.symbols {
            let Some(sec_idx) = sym.defining_section else { continue };
            // Find this section's NodeId by scanning graph.nodes. In the
            // ScanResult the flat NodeId layout is in the order we
            // pushed them, so we can reconstruct it arithmetically.
            let nid = node_id_of(&scan.graph, obj_idx as u32, sec_idx as u32);
            let Some(nid) = nid else { continue };
            let th = scan.trans_hash[nid as usize];
            match sym.bind {
                SymbolBind::Global | SymbolBind::Weak => {
                    global_hash.insert(sym.name.clone(), th);
                }
                SymbolBind::Local => {
                    local_hash.insert((sym.name.clone(), obj.tu_id), th);
                }
            }
        }
    }

    // Now walk the output ELF's symtab, emitting an entry for each symbol
    // we can resolve back to a trans_hash. STT_FILE markers partition
    // STB_LOCAL ranges by source TU — we track the current TU's tu_id
    // (computed identically to scan-side via blake3(stt_file_name)[:8])
    // and use it to disambiguate same-named locals across TUs in the
    // local_hash lookup.
    //
    // Critical: locals MUST round-trip through symhash. With LTO/fat,
    // every static (e.g. esp_println::LOCK) is a STB_LOCAL — if we
    // skip them, overlay's closure walk classifies them as Included,
    // which makes overlay re-allocate them at fresh addresses while
    // base is still using its own copy. The two halves of the program
    // end up with different views of every shared static.
    let mut entries: Vec<SymHashEntry> = Vec::new();
    let mut current_tu: Option<[u8; 8]> = None;
    for s in elf.symbols() {
        let name_raw = s.name().unwrap_or("");
        if matches!(s.kind(), object::SymbolKind::File) {
            current_tu = Some(tu_id_from_file_name(name_raw));
            continue;
        }
        // `is_definition()` in `object` 0.36 requires a real section
        // index, which excludes SHN_ABS — i.e. linker-script direct
        // assignments like `__udivdi3 = 0x40002544`. We still want
        // those: overlay's `compute_closure` needs to see ROM symbols
        // (esp32s3.rom.libgcc.ld) so calls into them resolve straight
        // to base's address rather than dragging compiler_builtins'
        // weak fallback into the closure. So accept anything that's
        // not undef and not a marker (FILE/SECTION/UNKNOWN).
        if s.is_undefined() { continue; }
        if matches!(
            s.kind(),
            object::SymbolKind::Section | object::SymbolKind::Unknown
        ) {
            continue;
        }
        if name_raw.is_empty() { continue; }
        let name = name_raw.to_string();

        let is_global = matches!(s.scope(), SymbolScope::Linkage | SymbolScope::Dynamic);
        if is_global {
            let Some(&th) = global_hash.get(&name) else { continue };
            entries.push(SymHashEntry {
                name,
                tu: None,
                trans_hash: th,
                address: s.address(),
                size: s.size() as u32,
            });
        } else {
            let Some(tu) = current_tu else { continue };
            let Some(&th) = local_hash.get(&(name.clone(), tu)) else { continue };
            entries.push(SymHashEntry {
                name,
                tu: Some(tu),
                trans_hash: th,
                address: s.address(),
                size: s.size() as u32,
            });
        }
    }
    entries.sort_by(|a, b| (a.name.as_str(), a.tu).cmp(&(b.name.as_str(), b.tu)));
    entries.dedup_by(|a, b| a.name == b.name && a.tu == b.tu);
    Ok(entries)
}

/// Same derivation as `elf::ParsedObject::tu_id` — blake3(file)[:8].
fn tu_id_from_file_name(name: &str) -> [u8; 8] {
    let digest = *blake3::hash(name.as_bytes()).as_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

fn node_id_of(graph: &crate::graph::Graph, object: u32, section: u32) -> Option<u32> {
    // graph.nodes was built by a nested loop over (obj, sec), pushing
    // NodeId sequentially — so for every object we can compute the base
    // NodeId as the sum of section counts in prior objects.
    // O(1) lookup: scan once, build a prefix table. Small graphs, not a
    // bottleneck, so linear scan is fine.
    let mut target: Option<u32> = None;
    for (nid, nm) in graph.nodes.iter().enumerate() {
        if nm.object == object && nm.section == section {
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

