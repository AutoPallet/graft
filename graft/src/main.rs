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

    graft::telemetry::log_link(
        &parsed,
        &real,
        input_bytes,
        output_bytes,
        elapsed,
        "passthrough",
    );

    match status {
        Ok(s) => s.code().map_or(ExitCode::FAILURE, |c| ExitCode::from(c as u8)),
        Err(e) => {
            eprintln!("graft: failed to exec real linker `{real}`: {e}");
            ExitCode::FAILURE
        }
    }
}
