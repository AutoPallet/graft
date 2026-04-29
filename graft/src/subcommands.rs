//! User-invokable graft subcommands. Dispatched from `main` based on
//! argv[1]. Keep each command small — they're diagnostic helpers, not
//! the main graft pipeline.

use std::path::Path;
use std::process::ExitCode;

use crate::{combine, elf_attach, metadata, scan};

pub fn cache_info(args: &[String]) -> ExitCode {
    let path = match args.first() {
        Some(p) => Path::new(p),
        None => {
            eprintln!("usage: graft cache-info <base.elf>");
            return ExitCode::from(2);
        }
    };
    match run_cache_info(path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft cache-info: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_cache_info(path: &Path) -> anyhow::Result<()> {
    let bytes = std::fs::read(path)?;
    let manifest_bytes = elf_attach::read_section(&bytes, metadata::SECTION_MANIFEST)?
        .ok_or_else(|| anyhow::anyhow!("no {} in {}", metadata::SECTION_MANIFEST, path.display()))?;
    let symhash_bytes = elf_attach::read_section(&bytes, metadata::SECTION_SYMHASH)?
        .ok_or_else(|| anyhow::anyhow!("no {} in {}", metadata::SECTION_SYMHASH, path.display()))?;

    let m = metadata::decode_manifest(manifest_bytes)?;
    let entries = metadata::decode_symhash(symhash_bytes)?;

    println!("manifest:");
    println!("  version          {}", m.version);
    println!("  base_abi         {}", hex(&m.base_abi));
    println!("  entry_symbol     {}", m.entry_symbol);
    println!("  toolchain_stamp  {}", m.toolchain_stamp);
    println!("  overlay_region   {:#x}..{:#x}", m.overlay_region.0, m.overlay_region.1);
    println!();
    println!("symhash: {} entries ({} bytes on disk)", entries.len(), symhash_bytes.len());

    if let Ok(pat) = std::env::var("GRAFT_GREP")
        && !pat.is_empty()
    {
        println!();
        println!("entries with symhash prefix matching {pat:?}:");
        for e in &entries {
            let hh: String = e.symhash.iter().map(|b| format!("{b:02x}")).collect();
            if hh.contains(&pat) {
                println!("  {:#010x}  sz={:<6} symhash={hh}", e.address, e.size);
            }
        }
    }
    if let Ok(addr_str) = std::env::var("GRAFT_ADDR")
        && let Ok(want) = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16)
    {
        println!();
        println!("entries at address {want:#x}:");
        for e in &entries {
            if e.address == want {
                let hh: String = e.symhash.iter().map(|b| format!("{b:02x}")).collect();
                println!("  {:#010x}  sz={:<6} symhash={hh}", e.address, e.size);
            }
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn combine(args: &[String]) -> ExitCode {
    // Positional: graft combine <base.elf> <overlay.elf> -o <out.elf>
    let mut base: Option<&str> = None;
    let mut overlay: Option<&str> = None;
    let mut out: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" => {
                if let Some(v) = args.get(i + 1) {
                    out = Some(v.as_str());
                    i += 2;
                    continue;
                }
            }
            a if a.starts_with("-o") => {
                out = Some(&a[2..]);
            }
            other if !other.starts_with('-') => {
                if base.is_none() {
                    base = Some(other);
                } else if overlay.is_none() {
                    overlay = Some(other);
                }
            }
            _ => {}
        }
        i += 1;
    }
    let (Some(base), Some(overlay), Some(out)) = (base, overlay, out) else {
        eprintln!("usage: graft combine <base.elf> <overlay.elf> -o <out.elf>");
        return ExitCode::from(2);
    };
    match combine::combine(Path::new(base), Path::new(overlay), Path::new(out)) {
        Ok(stats) => {
            eprintln!(
                "graft combine: overlay {} bytes at {:#x} · {} trampolines · combined {} bytes",
                stats.overlay_load_size,
                stats.overlay_vaddr,
                stats.trampolines.len(),
                stats.combined_size,
            );
            for t in &stats.trampolines {
                eprintln!("  {:#x} → {:#x}  {}", t.base_addr, t.overlay_addr, t.name);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("graft combine: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Scan a set of inputs and dump per-section content/reloc fingerprints.
/// Output is one line per allocated section, in a stable text format
/// suitable for diffing two scans of the "same" inputs (e.g. before
/// and after a source change) to see which sections drifted and why.
///
/// Format:
///   <obj-basename>	<section-name>	bytes=<hash>	relocs=<hash>	[reloc:target+addend ...]
///
/// `bytes` is blake3 of the section bytes (truncated to 8 bytes hex).
/// `relocs` is blake3 of postcard-encoded reloc list (same input
/// graft uses to compute per-section content-hash). Each reloc is
/// rendered as `<target>+<addend>` for inspection.
pub fn scan_dump(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("usage: graft scan-dump <input>...");
        return ExitCode::from(2);
    }
    let inputs: Vec<_> = args.iter().map(std::path::PathBuf::from).collect();
    let (eager, deferred): (Vec<_>, Vec<_>) = inputs.into_iter().partition(|p| {
        p.extension().and_then(|e| e.to_str()) != Some("a")
    });
    let scan_result = match scan::run(&eager, &deferred, &[], &[]) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("graft scan-dump: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    use std::io::Write;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let h8 = |bytes: &[u8]| -> String {
        bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
    };

    for (nid, nm) in scan_result.graph.nodes.iter().enumerate() {
        let trans_hash: String = scan_result.trans_hash[nid]
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        // One row per segment. Multi-segment nodes share a trans_hash;
        // bytes/relocs hashes are still per-segment so reviewers can
        // see the constituent inputs.
        for seg in &nm.segments {
            let obj = &scan_result.objects[seg.object as usize];
            let sec = &obj.sections[seg.section as usize];
            let obj_name = scan_result.inputs[seg.object as usize].label();

            let bytes_hash = h8(blake3::hash(&sec.bytes).as_bytes());
            let reloc_blob = postcard::to_allocvec(&sec.relocs).unwrap_or_default();
            let relocs_hash = h8(blake3::hash(&reloc_blob).as_bytes());

            let _ = write!(
                out,
                "{obj_name}\t{}\tbytes={bytes_hash}\trelocs={relocs_hash}\ttrans={trans_hash}",
                sec.name,
            );
            for r in &sec.relocs {
                let _ = write!(out, "\t{}+{}", r.target, r.addend);
            }
            let _ = writeln!(out);
        }
    }
    ExitCode::SUCCESS
}
