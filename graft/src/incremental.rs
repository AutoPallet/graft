//! Incremental mode: layout-preserving relink against a prior base.
//!
//! For now this is a stub — runs the real linker as passthrough but
//! verifies the base layout sidecar is present and decodable. The
//! actual layout-pinning logic (linker-script generation that pins
//! base sections to their original addresses, fail-on-grow, etc.) is
//! M1.g.

use std::process::{Command, ExitCode};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};

use crate::argv;
use crate::metadata::{decode_layout, BaseLayout};
use crate::telemetry;

pub fn link(argv: Vec<String>) -> ExitCode {
    match run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("graft incremental: {e:#}");
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

    // Locate base layout sidecar. If absent, the user asked for
    // incremental mode without first capturing a base — bail with a
    // clear message instead of silently producing a fresh layout.
    let mut layout_path = output.clone();
    layout_path.set_file_name(format!(
        "{}.graft-base.json",
        output.file_name().and_then(|s| s.to_str()).unwrap_or("link")
    ));
    if !layout_path.exists() {
        bail!(
            "no base layout at {} — run a clean build with GRAFT=base first",
            layout_path.display()
        );
    }
    let layout_bytes =
        std::fs::read(&layout_path).with_context(|| format!("read {}", layout_path.display()))?;
    let _layout: BaseLayout = decode_layout(&layout_bytes)?;

    // M1.g will: walk inputs, hash sections, diff against base layout,
    // generate linker-script overrides, run real linker with extra
    // `-Wl,-T,pin.x` flag. For now passthrough.
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
    let output_bytes = std::fs::metadata(&output).ok().map(|m| m.len());
    telemetry::log_link(
        &parsed,
        &real,
        input_bytes,
        output_bytes,
        elapsed,
        "incremental(stub)",
    );
    Ok(())
}
