use std::env;
use std::process::{Command, ExitCode};
use std::time::Instant;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if let Some(cmd) = args.get(1) {
        match cmd.as_str() {
            "cache-info" => return graft::subcommands::cache_info(&args[2..]),
            "combine" => return graft::subcommands::combine(&args[2..]),
            "snapshot" | "clean" => {
                eprintln!("graft: subcommand `{cmd}` not yet implemented");
                return ExitCode::from(2);
            }
            _ => {}
        }
    }

    match env::var("GRAFT").as_deref() {
        Ok("base") => graft::base::link(args),
        Ok("overlay") => graft::overlay::link(args),
        _ => passthrough(&args),
    }
}

fn passthrough(args: &[String]) -> ExitCode {
    // rustc drives the "linker" as a C compiler on most hosted targets
    // (gcc-driver flags like `-m64` and `-Wl,...` appear in argv). Default
    // to `cc`; bare-metal targets should set GRAFT_REAL_LD explicitly
    // (e.g. `xtensa-esp32s3-elf-gcc`) in .cargo/config.toml's `[env]`.
    let real = env::var("GRAFT_REAL_LD").unwrap_or_else(|_| "cc".into());

    // argv::parse expects the full argv (it skips index 0 itself); the
    // forwarded link args are everything after argv[0].
    let link_argv = &args[1..];
    let parsed = graft::argv::parse(args);
    let input_bytes: u64 = parsed
        .inputs
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.len()))
        .sum();

    let t0 = Instant::now();
    let status = Command::new(&real).args(link_argv).status();
    let elapsed = t0.elapsed();

    let output_bytes: Option<u64> = parsed
        .output
        .as_ref()
        .and_then(|p| std::fs::metadata(p).ok().map(|m| m.len()));

    // Per-link telemetry: append one line to a log file. We can't use
    // stderr because rustc captures the linker's stderr and filters
    // out non-diagnostic output. Default path: <output>.graft.log next
    // to the produced ELF — discoverable, target-isolated. Override
    // with $GRAFT_LOG.
    let log_path = env::var_os("GRAFT_LOG").map(std::path::PathBuf::from).or_else(|| {
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
    if let Some(p) = log_path
        && let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
    {
        use std::io::Write;
        let _ = writeln!(
            f,
            "{{\"ts\":{},\"real\":{:?},\"inputs\":{},\"input_bytes\":{},\"output_bytes\":{},\"elapsed_s\":{:.3}}}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            real,
            parsed.inputs.len(),
            input_bytes,
            output_bytes.map_or("null".into(), |b| b.to_string()),
            elapsed.as_secs_f64(),
        );
    }

    match status {
        Ok(s) => s.code().map_or(ExitCode::FAILURE, |c| ExitCode::from(c as u8)),
        Err(e) => {
            eprintln!("graft: failed to exec real linker `{real}`: {e}");
            ExitCode::FAILURE
        }
    }
}
