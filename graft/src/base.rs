//! Base mode: clean link with layout capture.
//!
//! Runs the real linker, then snapshots per-section layout (vaddr,
//! size, content hash, sh_flags) from the output ELF into
//! `<output>.graft-base.json`, and copies the ELF itself to
//! `<output>.graft-base.elf`. Incremental mode reads both back.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use object::{Object, ObjectSection, SectionFlags, elf};

use crate::argv;
use crate::metadata::{BaseLayout, GRAFT_MAGIC, SCHEMA_VERSION, SectionLayout, encode_layout};
use crate::telemetry;

pub fn link(argv: Vec<String>) -> ExitCode {
    match run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft base: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<()> {
    let parsed = argv::parse(&args);
    let output = parsed
        .output
        .clone()
        .ok_or_else(|| anyhow!("no -o <path> in argv"))?;

    let real = std::env::var("GRAFT_REAL_LD").unwrap_or_else(|_| "cc".into());
    let input_bytes: u64 = parsed
        .inputs
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.len()))
        .sum();

    let t0 = Instant::now();
    let status = Command::new(&real)
        .args(&args[1..])
        .status()
        .with_context(|| format!("exec {real}"))?;
    let elapsed = t0.elapsed();
    if !status.success() {
        bail!("real linker exited with {status}");
    }

    let elf_bytes =
        std::fs::read(&output).with_context(|| format!("read {}", output.display()))?;
    let layout = capture_layout(&elf_bytes).context("capture base layout")?;

    let layout_path = sidecar_path(&output, "graft-base.json");
    let elf_path = sidecar_path(&output, "graft-base.elf");
    let layout_bytes = encode_layout(&layout)?;
    std::fs::write(&layout_path, layout_bytes)
        .with_context(|| format!("write {}", layout_path.display()))?;
    std::fs::copy(&output, &elf_path)
        .with_context(|| format!("copy {} -> {}", output.display(), elf_path.display()))?;

    telemetry::log_link(
        &parsed,
        &real,
        input_bytes,
        Some(elf_bytes.len() as u64),
        elapsed,
        "base",
    );

    Ok(())
}

/// Snapshot the alloc'd loaded sections from the output ELF.
///
/// We skip non-alloc sections (`.symtab`, `.strtab`, `.debug.*`,
/// `.comment`, …) — they don't end up in the flashable image, so they
/// don't need to be pinned. Sections with `sh_addr == 0` are also
/// skipped as a sanity guard against accidentally including
/// scratch sections that the linker emitted but isn't actually placing.
fn capture_layout(elf_bytes: &[u8]) -> Result<BaseLayout> {
    let elf = object::File::parse(elf_bytes).context("parse output ELF")?;
    let mut sections: Vec<SectionLayout> = Vec::new();
    for sec in elf.sections() {
        let sh_flags = match sec.flags() {
            SectionFlags::Elf { sh_flags } => sh_flags,
            _ => 0,
        };
        let alloc = (sh_flags & u64::from(elf::SHF_ALLOC)) != 0;
        if !alloc {
            continue;
        }
        let vaddr = sec.address();
        if vaddr == 0 {
            continue;
        }
        let name = sec.name().unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        let bytes = sec.data().unwrap_or(&[]);
        let mut content_hash = [0u8; 16];
        content_hash.copy_from_slice(&blake3::hash(bytes).as_bytes()[..16]);
        sections.push(SectionLayout {
            name,
            vaddr,
            size: sec.size(),
            sh_flags,
            content_hash,
        });
    }
    sections.sort_by_key(|s| s.vaddr);
    Ok(BaseLayout {
        magic: GRAFT_MAGIC,
        version: SCHEMA_VERSION,
        toolchain_stamp: toolchain_stamp(),
        sections,
    })
}

fn toolchain_stamp() -> String {
    Command::new("rustc")
        .arg("-Vv")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("commit-hash: "))
                .unwrap_or("?")
                .to_string()
        })
        .unwrap_or_else(|| "?".into())
}

fn sidecar_path(output: &Path, suffix: &str) -> PathBuf {
    let mut p = output.to_path_buf();
    let name = format!(
        "{}.{}",
        output.file_name().and_then(|s| s.to_str()).unwrap_or("link"),
        suffix
    );
    p.set_file_name(name);
    p
}
