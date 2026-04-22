//! Parse the argv rustc hands us. We only care about three things:
//! the output path, the set of object-ish inputs (`.o`, `.rcgu.o`,
//! `.rlib`, `.a`), and everything else (passed through untouched when
//! we exec the real linker).

use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct LinkArgs {
    pub inputs: Vec<PathBuf>,
    pub output: Option<PathBuf>,
}

pub fn parse(argv: &[String]) -> LinkArgs {
    let mut out = LinkArgs::default();
    let mut i = 0;
    // argv[0] is graft itself when invoked as a command, or the linker
    // path when rustc passes argv — skip it either way by starting from 1.
    if argv.len() > 0 {
        i = 1;
    }
    while i < argv.len() {
        let a = &argv[i];
        if a == "-o" {
            if let Some(v) = argv.get(i + 1) {
                out.output = Some(PathBuf::from(v));
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("-o") {
            if !v.is_empty() {
                out.output = Some(PathBuf::from(v));
                i += 1;
                continue;
            }
        }
        if is_input(a) {
            out.inputs.push(PathBuf::from(a));
        }
        i += 1;
    }
    out
}

fn is_input(s: &str) -> bool {
    if s.starts_with('-') { return false; }
    let p = Path::new(s);
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
    matches!(ext, "o" | "rlib" | "a")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> { v.iter().map(|x| x.to_string()).collect() }

    #[test]
    fn basic_split() {
        let argv = s(&[
            "cc", "-m64", "/tmp/rustc/symbols.o",
            "/tmp/foo.rcgu.o", "/tmp/bar.rcgu.o",
            "-Wl,--as-needed", "-Wl,-Bstatic",
            "/tmp/libbase-abc.rlib",
            "-Wl,-Bdynamic", "-lgcc_s",
            "-o", "/tmp/out/app",
            "-nodefaultlibs",
        ]);
        let parsed = parse(&argv);
        assert_eq!(parsed.output.as_deref(), Some(Path::new("/tmp/out/app")));
        assert_eq!(parsed.inputs.len(), 4);
        assert!(parsed.inputs.iter().any(|p| p.ends_with("symbols.o")));
        assert!(parsed.inputs.iter().any(|p| p.ends_with("foo.rcgu.o")));
        assert!(parsed.inputs.iter().any(|p| p.ends_with("libbase-abc.rlib")));
    }

    #[test]
    fn attached_output_flag() {
        let argv = s(&["cc", "-o/tmp/out", "/tmp/foo.o"]);
        let parsed = parse(&argv);
        assert_eq!(parsed.output.as_deref(), Some(Path::new("/tmp/out")));
        assert_eq!(parsed.inputs.len(), 1);
    }
}
