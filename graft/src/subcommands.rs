//! User-invokable graft subcommands. Dispatched from `main` based on
//! argv[1]. Keep each command small — they're diagnostic helpers, not
//! the main graft pipeline.

use std::path::Path;
use std::process::ExitCode;

use crate::{elf_attach, metadata};

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
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
