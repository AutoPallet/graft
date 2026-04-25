//! Parse the argv rustc hands us. We only care about three things:
//! the output path, the set of object-ish inputs (`.o`, `.rcgu.o`,
//! `.rlib`, `.a`), and everything else (passed through untouched when
//! we exec the real linker).

use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct LinkArgs {
    pub inputs: Vec<PathBuf>,
    pub output: Option<PathBuf>,
    /// Symbols the link driver has declared "forced undefined" via `-u`
    /// / `--undefined` (either directly or via `-Wl,`). ld treats these
    /// as gc-sections roots, so we do too.
    pub undefined: Vec<String>,
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
        // -u SYM / -u=SYM / --undefined=SYM, either bare or wrapped as
        // `-Wl,-u,SYM` / `-Wl,--undefined=SYM`.
        if let Some(sym) = extract_undefined(a, argv.get(i + 1).map(|s| s.as_str())) {
            out.undefined.push(sym.rhs.into_owned());
            i += if sym.consumed_next { 2 } else { 1 };
            continue;
        }
        if is_input(a) {
            out.inputs.push(PathBuf::from(a));
        }
        i += 1;
    }
    out
}

struct Undefined<'a> {
    rhs: std::borrow::Cow<'a, str>,
    consumed_next: bool,
}

fn extract_undefined<'a>(cur: &'a str, next: Option<&'a str>) -> Option<Undefined<'a>> {
    // `-u SYM` / `--undefined SYM`
    if cur == "-u" || cur == "--undefined" {
        return next.map(|s| Undefined { rhs: s.into(), consumed_next: true });
    }
    // `-uSYM` / `--undefined=SYM`
    if let Some(s) = cur.strip_prefix("-u")
        && !s.is_empty()
        && !s.starts_with('-')
    {
        return Some(Undefined { rhs: s.into(), consumed_next: false });
    }
    if let Some(s) = cur.strip_prefix("--undefined=") {
        return Some(Undefined { rhs: s.into(), consumed_next: false });
    }
    // `-Wl,-u,SYM` / `-Wl,--undefined=SYM` / `-Wl,--undefined,SYM`
    if let Some(rest) = cur.strip_prefix("-Wl,") {
        let parts: Vec<&str> = rest.split(',').collect();
        let mut it = parts.iter().copied();
        while let Some(tok) = it.next() {
            match tok {
                "-u" | "--undefined" => {
                    if let Some(s) = it.next() {
                        return Some(Undefined { rhs: s.to_string().into(), consumed_next: false });
                    }
                }
                _ => {
                    if let Some(s) = tok.strip_prefix("--undefined=") {
                        return Some(Undefined { rhs: s.to_string().into(), consumed_next: false });
                    }
                    if let Some(s) = tok.strip_prefix("-u") {
                        if !s.is_empty() && !s.starts_with('-') {
                            return Some(Undefined { rhs: s.to_string().into(), consumed_next: false });
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn is_input(s: &str) -> bool {
    if s.starts_with('-') { return false; }
    let p = Path::new(s);
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
    matches!(ext, "o" | "rlib" | "a")
}

/// Walk rustc-provided link argv, yielding everything overlay mode
/// wants to forward verbatim to the real linker — that is, everything
/// EXCEPT the inputs (replaced by the pruned objects) and the `-o`
/// output flag (replaced by overlay's own output path).
///
/// Rationale: the overlay link should mirror base's link as closely
/// as possible — same `-l libs`, same `-L` paths, same `-T` scripts,
/// same `-Wl,...` linker options. Hand-curating the subset we need
/// is fragile (e.g. `-l esp_rom_sys` whose stub library is itself a
/// linker script that PROVIDES ROM addresses for `__udivdi3` etc.).
/// Passthrough keeps overlay aligned with whatever flags base built
/// with for free, and any divergence becomes a deliberate override
/// rather than an oversight.
pub fn forwarded_link_args(argv: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = if argv.is_empty() { 0 } else { 1 };
    while i < argv.len() {
        let a = &argv[i];
        if is_input(a) { i += 1; continue; }
        if a == "-o" { i += 2; continue; }
        if a.starts_with("-o") && a.len() > 2 { i += 1; continue; }
        out.push(a.as_str());
        i += 1;
    }
    out
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

    #[test]
    fn extract_u_flags() {
        let argv = s(&[
            "cc",
            "-u", "foo1",
            "-ufoo2",
            "--undefined=foo3",
            "-Wl,-u,foo4",
            "-Wl,--undefined=foo5",
            "-Wl,--undefined,foo6",
            "-Wl,-ufoo7",
            "-o", "/tmp/out",
            "/tmp/foo.o",
        ]);
        let parsed = parse(&argv);
        assert_eq!(
            parsed.undefined,
            vec!["foo1", "foo2", "foo3", "foo4", "foo5", "foo6", "foo7"],
        );
    }
}
