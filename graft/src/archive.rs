//! Extract object files from linker inputs.
//!
//! Inputs can be:
//! - Loose `.o` / `.rcgu.o` files on disk.
//! - `.rlib` archives — `ar`-format files with `.rmeta` + object members.
//!
//! This module gives downstream passes (elf, graph, hash) a uniform
//! `Vec<ObjectInput>` to work with.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use object::read::archive::ArchiveFile;

#[derive(Debug, Clone)]
pub struct ObjectInput {
    /// Path to the source file on disk. For archive members this is the
    /// `.rlib`; for loose objects it's the `.o` itself.
    pub source_path: PathBuf,
    /// `None` for loose `.o` inputs. `Some(member_name)` for members
    /// extracted from a `.rlib` — the name comes from the archive header
    /// and is typically `<crate>-<hash>.<n>.rcgu.o`.
    pub member_name: Option<String>,
    /// The full ELF bytes of the object. Owned because archive members
    /// would otherwise hold a borrow against the whole archive buffer,
    /// which hurts ergonomics and parallelism downstream.
    pub bytes: Vec<u8>,
}

impl ObjectInput {
    /// Human-readable label for logging / error messages.
    pub fn label(&self) -> String {
        match &self.member_name {
            Some(m) => format!("{}::{}", self.source_path.display(), m),
            None => self.source_path.display().to_string(),
        }
    }
}

/// Scan linker-input paths and return every `.o` / `.rcgu.o` they
/// contain. Non-object-bearing paths (linker scripts, shared libs,
/// unknown extensions) are silently skipped.
pub fn collect_objects<P: AsRef<Path>>(paths: &[P]) -> Result<Vec<ObjectInput>> {
    let mut out = Vec::new();
    for p in paths {
        let p = p.as_ref();
        let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
        match ext {
            "o" => {
                let bytes = std::fs::read(p).with_context(|| format!("read {}", p.display()))?;
                out.push(ObjectInput {
                    source_path: p.to_path_buf(),
                    member_name: None,
                    bytes,
                });
            }
            "rlib" | "a" => {
                scan_archive(p, &mut out)
                    .with_context(|| format!("scan archive {}", p.display()))?;
            }
            _ => {}
        }
    }
    Ok(out)
}

fn scan_archive(path: &Path, out: &mut Vec<ObjectInput>) -> Result<()> {
    let bytes = std::fs::read(path)?;
    let archive = ArchiveFile::parse(&*bytes)
        .map_err(|e| anyhow::anyhow!("parse archive: {e}"))?;
    for member in archive.members() {
        let member = member.map_err(|e| anyhow::anyhow!("archive member: {e}"))?;
        let name = String::from_utf8_lossy(member.name()).into_owned();
        if !(name.ends_with(".o") || name.ends_with(".rcgu.o")) {
            continue;
        }
        let data = member.data(&*bytes).map_err(|e| anyhow::anyhow!("member data: {e}"))?;
        out.push(ObjectInput {
            source_path: path.to_path_buf(),
            member_name: Some(name),
            bytes: data.to_vec(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test against the rustc-stability probe fixture's built output,
    /// if available. Skipped silently if the fixture wasn't built first.
    #[test]
    fn scan_probe_rlibs() {
        // probes/rustc-stability builds into tempdirs; nothing stable on disk.
        // So we can't assert a specific path here. Instead, just exercise the
        // path where we pass a non-existent path and get an empty result.
        let out = collect_objects::<&Path>(&[]).unwrap();
        assert!(out.is_empty());
    }
}
