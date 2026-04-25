//! Base mode: the first, from-scratch link.
//!
//! Pre-scan runs in a background thread while the real linker does its
//! work on the same inputs — hashing hides under the linker's runtime.
//! After the link lands, we re-open the output ELF for `.symtab`
//! addresses, join them with the pre-scan's trans_hashes, and attach
//! `.graft.manifest` + `.graft.symhash` as SHF_ALLOC=0 sections.

use std::io::Write;
use std::path::PathBuf;
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
    let link_args = argv::parse(&argv);
    let output = link_args.output.clone().ok_or_else(|| anyhow!("no -o <path> in argv"))?;

    let t_start = std::time::Instant::now();

    // Spawn pre-scan concurrently with the real linker. Both touch the
    // same files (read-only), so there's no contention.
    let scan_inputs: Vec<PathBuf> = link_args.inputs.clone();
    let scan_handle = std::thread::spawn(move || scan::run(&scan_inputs));

    let ld_status = exec_real_linker(&argv)?;
    let scan_result = scan_handle
        .join()
        .map_err(|_| anyhow!("pre-scan thread panicked"))?
        .context("pre-scan failed")?;

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
        "graft base: {} objects · {} sections · {} symhash entries · link+scan {:.1?} · attach {:.1?} · total {:.1?}",
        scan_result.objects.len(),
        scan_result.graph.nodes.len(),
        entries.len(),
        t_parallel,
        t_post.elapsed(),
        t_total,
    );
    Ok(())
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
    // we can resolve back to a trans_hash.
    let mut entries: Vec<SymHashEntry> = Vec::new();
    for s in elf.symbols() {
        if !s.is_definition() { continue; }
        let name = s.name().unwrap_or("").to_string();
        if name.is_empty() { continue; }

        // We only have trans_hash for globals (by name) in the output's
        // .symtab, because locals in the .o were internalized and have
        // different namespacing after link. For M0.5 this is fine —
        // most of what overlay mode looks up is callable globals anyway.
        let is_global = matches!(s.scope(), SymbolScope::Linkage | SymbolScope::Dynamic);
        if !is_global {
            continue;
        }
        let Some(&th) = global_hash.get(&name) else { continue };
        entries.push(SymHashEntry {
            name,
            tu: None,
            trans_hash: th,
            address: s.address(),
            size: s.size() as u32,
        });
    }
    entries.sort_by(|a, b| (a.name.as_str(), a.tu).cmp(&(b.name.as_str(), b.tu)));
    entries.dedup_by(|a, b| a.name == b.name && a.tu == b.tu);
    Ok(entries)
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
    // On hosted Linux the real entry (`_start`) is libc's, but the
    // user-level entry we care about is `main`. Just hard-code for
    // M0.5 — the manifest field is informational.
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

