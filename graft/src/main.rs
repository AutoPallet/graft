use std::env;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if let Some(cmd) = args.get(1) {
        match cmd.as_str() {
            "snapshot" | "combine" | "cache-info" | "clean" => {
                eprintln!("graft: subcommand `{cmd}` not yet implemented");
                return ExitCode::from(2);
            }
            _ => {}
        }
    }

    match env::var("GRAFT").as_deref() {
        Ok("base") => {
            eprintln!("graft: base mode not yet implemented");
            ExitCode::from(2)
        }
        Ok("overlay") => {
            eprintln!("graft: overlay mode not yet implemented");
            ExitCode::from(2)
        }
        _ => passthrough(&args[1..]),
    }
}

fn passthrough(argv: &[String]) -> ExitCode {
    let real = env::var("GRAFT_REAL_LD").unwrap_or_else(|_| "ld".into());
    let status = Command::new(&real).args(argv).status();
    match status {
        Ok(s) => s.code().map_or(ExitCode::FAILURE, |c| ExitCode::from(c as u8)),
        Err(e) => {
            eprintln!("graft: failed to exec real linker `{real}`: {e}");
            ExitCode::FAILURE
        }
    }
}
