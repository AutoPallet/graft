//! Per-link telemetry. Always-on; one JSON line per link invocation.

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use crate::argv::LinkArgs;

/// Append one telemetry line to `<output>.graft.log` (override with
/// `$GRAFT_LOG`). rustc captures the linker's stderr and filters
/// non-diagnostic output, so file logging is the only reliable channel.
pub fn log_link(
    parsed: &LinkArgs,
    real: &str,
    input_bytes: u64,
    output_bytes: Option<u64>,
    elapsed: Duration,
    mode: &str,
) {
    let log_path = env::var_os("GRAFT_LOG").map(PathBuf::from).or_else(|| {
        parsed.output.as_ref().map(|p| {
            let mut q = p.clone();
            let name = format!(
                "{}.graft.log",
                p.file_name().and_then(|s| s.to_str()).unwrap_or("link")
            );
            q.set_file_name(name);
            q
        })
    });
    let Some(p) = log_path else { return };
    let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) else {
        return;
    };
    use std::io::Write;
    let _ = writeln!(
        f,
        "{{\"ts\":{},\"mode\":{:?},\"real\":{:?},\"inputs\":{},\"input_bytes\":{},\"output_bytes\":{},\"elapsed_s\":{:.3}}}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        mode,
        real,
        parsed.inputs.len(),
        input_bytes,
        output_bytes.map_or("null".into(), |b| b.to_string()),
        elapsed.as_secs_f64(),
    );
}
