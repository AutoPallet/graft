//! User-invokable graft subcommands. Dispatched from `main` based on
//! argv[1]. Keep each command small — they're diagnostic helpers, not
//! the main graft pipeline.

use std::path::Path;
use std::process::ExitCode;

use crate::{combine, elf_attach, metadata};

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
    let globals = entries.iter().filter(|e| e.tu.is_none()).count();
    let locals = entries.len() - globals;
    println!("  {globals} globals, {locals} locals");

    if let Ok(pat) = std::env::var("GRAFT_GREP")
        && !pat.is_empty()
    {
        println!();
        println!("entries matching {pat:?}:");
        for e in &entries {
            if e.name.contains(&pat) {
                let scope = if e.tu.is_some() { "L" } else { "G" };
                let hh: String = e.trans_hash[..6].iter().map(|b| format!("{b:02x}")).collect();
                println!(
                    "  {:#010x}  sz={:<6} {scope} {hh} {}",
                    e.address, e.size, e.name
                );
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
