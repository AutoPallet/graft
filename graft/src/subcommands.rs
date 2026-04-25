//! User-invokable graft subcommands. Dispatched from `main` based on
//! argv[1]. Keep each command small — they're diagnostic helpers, not
//! the main graft pipeline.

use std::path::Path;
use std::process::ExitCode;

use crate::metadata::{decode_layout, BaseLayout};

pub fn cache_info(args: &[String]) -> ExitCode {
    let path = match args.first() {
        Some(p) => Path::new(p),
        None => {
            eprintln!("usage: graft cache-info <base.elf>");
            eprintln!("  reads <base.elf>.graft-base.json next to it");
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

fn run_cache_info(elf_path: &Path) -> anyhow::Result<()> {
    let mut layout_path = elf_path.to_path_buf();
    layout_path.set_file_name(format!(
        "{}.graft-base.json",
        elf_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("link")
    ));
    let bytes = std::fs::read(&layout_path)?;
    let layout: BaseLayout = decode_layout(&bytes)?;

    println!("layout: {}", layout_path.display());
    println!("  version          {}", layout.version);
    println!("  toolchain_stamp  {}", layout.toolchain_stamp);
    println!("  sections         {}", layout.sections.len());
    let total: u64 = layout.sections.iter().map(|s| s.size).sum();
    println!("  total bytes      {total}");
    println!();
    println!("first 8 sections by vaddr:");
    for s in layout.sections.iter().take(8) {
        println!(
            "  {:#012x}  {:>7}B  flags={:#x}  {}",
            s.vaddr, s.size, s.sh_flags, s.name
        );
    }
    Ok(())
}
