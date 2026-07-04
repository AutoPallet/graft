//! `GRAFT=auto` — self-managing base/overlay selection in the linker
//! seat (docs: task #21; "cargo bflash just works").
//!
//! graft decides, not a wrapper script: only the linker invocation can
//! see whether a base snapshot exists for *this* output, whether the
//! manifest still matches the link's shape, and whether the overlay
//! closure fits slack. The rules:
//!
//!   1. No snapshot for this output (or `GRAFT_REBASE=1`) → full base
//!      link, then copy the attached output to the snapshot path.
//!   2. Snapshot exists → overlay against it. On success the snapshot
//!      is untouched (every overlay is against the same base — chained
//!      overlays are #31, not this).
//!   3. Overlay fails FOR ANY REASON → one loud line with the reason,
//!      then a full base relink and a fresh snapshot. Overlay failures
//!      are bails by design (slack overflow, resolution refusals,
//!      manifest/schema drift, argv reshapes) — the fallback converts
//!      every one of them into "the build still succeeds, just slower".
//!
//! The snapshot lives at `<output dir>/.graft-auto/<output>.base.elf`:
//! per-output (concurrent links of different binaries don't collide),
//! inside the target dir (a full `cargo clean` wipes it, which is
//! exactly right), but NOT prefixed with the artifact stem — `cargo
//! clean -p <crate>` deletes stem-prefixed files, and that common
//! force-rebuild idiom must cost an overlay, not a full base relink.
//! Delete the dir (or set `GRAFT_REBASE=1`) to force a fresh base.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};

pub fn link(argv: Vec<String>) -> ExitCode {
    match run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft auto: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// `<output dir>/.graft-auto/<output file name>.base.elf`. NOT
/// stem-prefixed (see module doc: `cargo clean -p` must not eat it),
/// and the file name is appended verbatim — cargo outputs like
/// `deploy-25737f13f51b6bad` have hash "extensions" that must survive.
pub fn snapshot_path(output: &Path) -> PathBuf {
    let dir = output.parent().unwrap_or_else(|| Path::new("."));
    let mut name = output
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("link"))
        .to_os_string();
    name.push(".base.elf");
    dir.join(".graft-auto").join(name)
}

/// Strict `GRAFT_REBASE` parse: unset/"" → false, "1" → true, anything
/// else is a hard error (same never-guess policy as `GRAFT`/`GRAFT_ICF`).
fn rebase_requested() -> Result<bool> {
    match std::env::var("GRAFT_REBASE") {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(e) => Err(anyhow!("GRAFT_REBASE: {e}")),
        Ok(v) => match v.as_str() {
            "" | "0" => Ok(false),
            "1" => Ok(true),
            other => bail!("GRAFT_REBASE={other:?} is not recognized (expected `1`)"),
        },
    }
}

/// Record an auto-mode decision. rustc filters the linker's stderr on
/// successful links, so stderr alone makes auto's choices invisible —
/// mirror every decision into the graft log file (`$GRAFT_LOG`, or
/// `<output dir>/<output>.graft.log`), same channel telemetry uses.
fn note(output: &Path, msg: &str) {
    eprintln!("graft auto: {msg}");
    let log_path = std::env::var_os("GRAFT_LOG").map(PathBuf::from).unwrap_or_else(|| {
        let mut q = output.to_path_buf();
        let name = format!(
            "{}.graft.log",
            output.file_name().and_then(|s| s.to_str()).unwrap_or("link")
        );
        q.set_file_name(name);
        q
    });
    if let Ok(mut f) =
        std::fs::OpenOptions::new().create(true).append(true).open(&log_path)
    {
        use std::io::Write;
        let _ = writeln!(f, "graft auto: {msg}");
    }
}

fn run(argv: Vec<String>) -> Result<()> {
    let output = crate::argv::parse(&argv)
        .output
        .ok_or_else(|| anyhow!("no -o <path> in argv"))?;
    let snapshot = snapshot_path(&output);

    if rebase_requested()? {
        note(&output, "GRAFT_REBASE=1 → full base link");
    } else if snapshot.exists() {
        note(&output, &format!("overlay against {}", snapshot.display()));
        match crate::overlay::run_with_base(argv.clone(), snapshot.clone()) {
            Ok(()) => return Ok(()),
            Err(e) => {
                note(
                    &output,
                    &format!("overlay failed ({e:#}) → falling back to full base relink"),
                );
            }
        }
    } else {
        note(
            &output,
            &format!("no base snapshot at {} → base link", snapshot.display()),
        );
    }

    crate::base::run(argv)?;
    // Snapshot the attached output so the next link overlays against
    // it. Copy AFTER base::run: the manifest is embedded during attach.
    if let Some(dir) = snapshot.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create {}", dir.display()))?;
    }
    std::fs::copy(&output, &snapshot).with_context(|| {
        format!("snapshot {} -> {}", output.display(), snapshot.display())
    })?;
    note(&output, &format!("base snapshot refreshed at {}", snapshot.display()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_path_shape() {
        // Sibling hidden dir (never stem-prefixed — `cargo clean -p`
        // deletes stem-prefixed files), full file name preserved.
        assert_eq!(
            snapshot_path(Path::new("/t/deps/deploy-25737f13f51b6bad")),
            Path::new("/t/deps/.graft-auto/deploy-25737f13f51b6bad.base.elf")
        );
        assert_eq!(
            snapshot_path(Path::new("/t/app.elf")),
            Path::new("/t/.graft-auto/app.elf.base.elf")
        );
    }
}
