//! User-invokable graft subcommands. Dispatched from `main` based on
//! argv[1]. Keep each command small — they're diagnostic helpers, not
//! the main graft pipeline.

use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;

use crate::{combine, elf_attach, metadata, scan};

pub fn cache_info(args: &[String]) -> ExitCode {
    // Positional <base.elf>, plus optional section-table filters:
    //   --grep <substr>  only entries whose trans_hash hex contains it
    //   --addr <addr>    only entries at this address (hex, 0x-optional)
    let mut path: Option<&str> = None;
    let mut grep: Option<&str> = None;
    let mut addr: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--grep" => {
                grep = args.get(i + 1).map(String::as_str);
                i += 2;
            }
            "--addr" => {
                addr = args.get(i + 1).map(String::as_str);
                i += 2;
            }
            other if !other.starts_with('-') && path.is_none() => {
                path = Some(other);
                i += 1;
            }
            _ => i += 1,
        }
    }
    let Some(path) = path else {
        eprintln!("usage: graft cache-info <base.elf> [--grep <substr>] [--addr <addr>]");
        return ExitCode::from(2);
    };
    match run_cache_info(Path::new(path), grep, addr) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft cache-info: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_cache_info(path: &Path, grep: Option<&str>, addr: Option<&str>) -> anyhow::Result<()> {
    let bytes = std::fs::read(path)?;
    let manifest_bytes = elf_attach::read_section(&bytes, metadata::SECTION_MANIFEST)?
        .ok_or_else(|| anyhow::anyhow!("no {} in {}", metadata::SECTION_MANIFEST, path.display()))?;
    let sections_bytes = elf_attach::read_section(&bytes, metadata::SECTION_SECTIONS)?
        .ok_or_else(|| anyhow::anyhow!("no {} in {}", metadata::SECTION_SECTIONS, path.display()))?;

    let m = metadata::decode_manifest(manifest_bytes)?;
    let table = metadata::decode_sections(sections_bytes)?;

    println!("manifest:");
    println!("  version          {}", m.version);
    println!("  hash_algo        {}", m.hash_algo_version);
    if m.version != metadata::SCHEMA_VERSION
        || m.hash_algo_version != metadata::HASH_ALGO_VERSION
    {
        println!(
            "  ⚠ STALE: this graft is schema v{} / hash-algo v{} — the \
             printed trans_hash values are not comparable to current ones",
            metadata::SCHEMA_VERSION,
            metadata::HASH_ALGO_VERSION
        );
    }
    println!("  base_abi         {}", hex(&m.base_abi));
    println!("  entry_symbol     {}", m.entry_symbol);
    println!("  toolchain_stamp  {}", m.toolchain_stamp);
    println!("  overlay_region   {:#x}..{:#x}", m.overlay_region.0, m.overlay_region.1);
    for a in &m.aggregator_hashes {
        println!("  aggregator       {} {}", a.id, hex(&a.trans_hash));
    }
    println!();
    println!(
        "sections: {} entries, {} ambiguous ({} bytes on disk)",
        table.entries.len(),
        table.ambiguous.len(),
        sections_bytes.len()
    );

    if let Some(pat) = grep.filter(|p| !p.is_empty()) {
        println!();
        println!("entries with trans_hash prefix matching {pat:?}:");
        for e in &table.entries {
            let hh: String = e.trans_hash.iter().map(|b| format!("{b:02x}")).collect();
            if hh.contains(pat) {
                println!("  {:#010x}  trans_hash={hh}", e.address);
            }
        }
    }
    if let Some(addr_str) = addr {
        let want = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16)
            .with_context(|| format!("--addr {addr_str:?}: not a hex address"))?;
        println!();
        println!("entries at address {want:#x}:");
        for e in &table.entries {
            if e.address == want {
                let hh: String = e.trans_hash.iter().map(|b| format!("{b:02x}")).collect();
                println!("  {:#010x}  trans_hash={hh}", e.address);
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

/// Replay scan + map-recovery against an existing base link and print
/// every trans_hash the linker placed at more than one address —
/// content-identical sections ld kept as separate copies (it has no
/// ICF). Nothing is relinked; needs the link argv (one arg per line),
/// the linked ELF, and its linker map.
pub fn dup_stats(args: &[String]) -> ExitCode {
    let mut argv_file: Option<&str> = None;
    let mut elf: Option<&str> = None;
    let mut map: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--argv" => {
                argv_file = args.get(i + 1).map(String::as_str);
                i += 2;
            }
            "--elf" => {
                elf = args.get(i + 1).map(String::as_str);
                i += 2;
            }
            "--map" => {
                map = args.get(i + 1).map(String::as_str);
                i += 2;
            }
            _ => i += 1,
        }
    }
    let (Some(argv_file), Some(elf), Some(map)) = (argv_file, elf, map) else {
        eprintln!("usage: graft dup-stats --argv <argv-file> --elf <base.elf> --map <link.map>");
        return ExitCode::from(2);
    };
    match crate::base::dup_stats(Path::new(argv_file), Path::new(elf), Path::new(map)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft dup-stats: {e:#}");
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
    let scan_result = match scan::run(&eager, &deferred, &[], &[], None) {
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
