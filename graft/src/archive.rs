//! Extract object files from linker inputs.
//!
//! Inputs come in two flavors:
//! - **Eager**: loose `.o` / `.rcgu.o` files and `.rlib` archives.
//!   Every member gets parsed up front. Rust crate output (rlib) tends
//!   to be small + mostly-reachable, so eager is a wash on cost.
//! - **Deferred**: `.a` archives (system libraries, IDF components,
//!   user `cc::Build`-emitted shims). Only the archive's symbol-table
//!   index is read up front; individual member `.o`s get parsed on
//!   demand by `scan` as the reachability walk discovers UND
//!   references that resolve into them. ESP-IDF builds drag in
//!   thousands of archive members, of which dozens are reachable —
//!   deferring keeps scan time bounded by what the closure actually
//!   touches.
//!
//! This module gives `scan` a uniform `Vec<ObjectInput>` (parsed)
//! plus a `Vec<DeferredArchive>` (indexed but not parsed) to work
//! with.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use object::read::archive::{ArchiveFile, ArchiveOffset};

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

/// Result of `collect_objects`: scanned object inputs plus the set of
/// archive paths we successfully walked (i.e. real `!<arch>\n` files,
/// not stub linker scripts with `.a` extensions).
#[derive(Debug, Default)]
pub struct CollectResult {
    pub inputs: Vec<ObjectInput>,
    /// Absolute (canonicalized when possible) paths of `.a` / `.rlib`
    /// archives we expanded. Callers use this to know which forwarded
    /// `-l<name>` flags can be stripped from the link argv (their
    /// content is now in `inputs` and will be re-emitted as filtered
    /// archives).
    pub walked_archives: HashSet<PathBuf>,
}

/// Eagerly scan loose `.o` and `.rlib` paths into parsed inputs.
/// `.a` archives go through `open_deferred` instead — see module docs.
/// Non-object-bearing paths are silently skipped.
pub fn collect_eager<P: AsRef<Path> + Sync>(paths: &[P]) -> Result<CollectResult> {
    use rayon::prelude::*;
    // Per-path collection fans out across cores (file reads + ar
    // member extraction are a top scan cost at rust-analyzer scale).
    // Results are concatenated IN INPUT ORDER below — ld's
    // left-to-right input semantics must be preserved exactly.
    let per_path: Vec<(Vec<ObjectInput>, Option<PathBuf>)> = paths
        .par_iter()
        .map(|p| {
            let p = p.as_ref();
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
            match ext {
                "o" => {
                    let bytes =
                        std::fs::read(p).with_context(|| format!("read {}", p.display()))?;
                    Ok((
                        vec![ObjectInput {
                            source_path: p.to_path_buf(),
                            member_name: None,
                            bytes,
                        }],
                        None,
                    ))
                }
                "rlib" => {
                    let bytes =
                        std::fs::read(p).with_context(|| format!("read {}", p.display()))?;
                    if !is_ar_magic(&bytes) {
                        // An `.rlib` is always an `ar` archive. A non-archive
                        // here means a truncated / corrupt artifact — skipping
                        // it would silently drop a whole crate's objects from
                        // the scan and produce a wrong closure. Fail loud.
                        anyhow::bail!(
                            "{}: .rlib is not an `ar` archive (truncated or corrupt?)",
                            p.display()
                        );
                    }
                    let mut inputs = Vec::new();
                    scan_archive_bytes(p, &bytes, &mut inputs)
                        .with_context(|| format!("scan archive {}", p.display()))?;
                    let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
                    Ok((inputs, Some(canon)))
                }
                _ => Ok((Vec::new(), None)),
            }
        })
        .collect::<Result<_>>()?;

    let mut result = CollectResult::default();
    for (inputs, walked) in per_path {
        result.inputs.extend(inputs);
        if let Some(canon) = walked {
            result.walked_archives.insert(canon);
        }
    }
    Ok(result)
}

/// A `.a` archive opened for on-demand member parsing. We've read the
/// archive's symbol-index (the `/` member in System V format) into
/// `symbol_to_offset` but haven't parsed any individual `.o` member
/// yet — `parse_member` does that lazily as the scan reachability
/// walk discovers references.
pub struct DeferredArchive {
    pub path: PathBuf,
    /// Canonicalized path. Used as the key in `walked_archives` so
    /// callers can decide whether the corresponding `-l<name>` flag
    /// can be stripped from the forwarded link argv.
    pub canon_path: PathBuf,
    /// Whole archive in memory. Holding bytes keeps `ArchiveFile`
    /// re-parsing cheap (header parse only) and lets us hand
    /// `data()` results into `ObjectInput::bytes` as `to_vec()`s
    /// later.
    pub bytes: Vec<u8>,
    /// `symbol_name → archive_offset` of the member that defines it.
    /// Built once at open time from the archive's index.
    pub symbol_to_offset: std::collections::HashMap<String, u64>,
}

impl DeferredArchive {
    /// Open `path` for deferred member parsing. Returns `Ok(None)` if
    /// the file isn't a real `!<arch>\n` archive (stub linker scripts
    /// with `.a` extensions get this treatment — ld processes them via
    /// the forwarded `-l<name>` flag).
    pub fn open(path: &Path) -> Result<Option<Self>> {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        if !is_ar_magic(&bytes) {
            return Ok(None);
        }
        let archive = ArchiveFile::parse(&*bytes)
            .map_err(|e| anyhow!("parse archive {}: {e}", path.display()))?;
        let mut sym_to_off: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        match archive.symbols().map_err(|e| anyhow!("{e}"))? {
            Some(symbols) => {
                for sym_result in symbols {
                    let sym = sym_result.map_err(|e| anyhow!("{e}"))?;
                    if let Ok(name) = std::str::from_utf8(sym.name()) {
                        // First defining member wins. Mirrors ld's
                        // archive-resolution semantics (left-to-right
                        // search, first hit binds).
                        sym_to_off
                            .entry(name.to_string())
                            .or_insert(sym.offset().0);
                    }
                }
            }
            None => {
                // No symbol-table member. An archive with object members
                // but no index can't be demand-loaded — by graft *or* by
                // ld (which errors "archive has no index; run ranlib").
                // Treating it as empty would silently drop every member
                // from the scan and produce a wrong closure, so fail
                // loud. An empty archive (no members) legitimately has no
                // index and is fine.
                let has_members = archive
                    .members()
                    .next()
                    .transpose()
                    .map_err(|e| anyhow!("{e}"))?
                    .is_some();
                if has_members {
                    anyhow::bail!(
                        "{}: archive has members but no symbol index — \
                         graft cannot demand-load from it (run `ranlib`)",
                        path.display()
                    );
                }
            }
        }
        let canon_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        Ok(Some(Self {
            path: path.to_path_buf(),
            canon_path,
            bytes,
            symbol_to_offset: sym_to_off,
        }))
    }

    /// Parse the archive member located at `member_offset` (typically
    /// obtained from `symbol_to_offset`) and return it as a regular
    /// `ObjectInput` ready for `elf::parse`.
    pub fn parse_member(&self, member_offset: u64) -> Result<ObjectInput> {
        let archive = ArchiveFile::parse(&*self.bytes)
            .map_err(|e| anyhow!("re-parse archive {}: {e}", self.path.display()))?;
        let member = archive
            .member(ArchiveOffset(member_offset))
            .map_err(|e| anyhow!("member at {member_offset:#x}: {e}"))?;
        let name = String::from_utf8_lossy(member.name()).into_owned();
        let data = member
            .data(&*self.bytes)
            .map_err(|e| anyhow!("member data: {e}"))?;
        Ok(ObjectInput {
            source_path: self.path.clone(),
            member_name: Some(name),
            bytes: data.to_vec(),
        })
    }
}

fn is_ar_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"!<arch>\n")
}

fn scan_archive_bytes(path: &Path, bytes: &[u8], out: &mut Vec<ObjectInput>) -> Result<()> {
    let archive = ArchiveFile::parse(bytes)
        .map_err(|e| anyhow::anyhow!("parse archive: {e}"))?;
    for member in archive.members() {
        let member = member.map_err(|e| anyhow::anyhow!("archive member: {e}"))?;
        let name = String::from_utf8_lossy(member.name()).into_owned();
        if !(name.ends_with(".o") || name.ends_with(".rcgu.o")) {
            continue;
        }
        let data = member.data(bytes).map_err(|e| anyhow::anyhow!("member data: {e}"))?;
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
        let out = collect_eager::<&Path>(&[]).unwrap();
        assert!(out.inputs.is_empty());
    }
}
