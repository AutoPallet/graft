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
    /// `-l<name>` flags rustc / gcc forwarded — each names an archive
    /// (`lib<name>.a`) ld would search for and link. We resolve them
    /// against `library_paths` so scan can walk them like any other
    /// `.a` input.
    pub libs: Vec<String>,
    /// `-L<path>` library-search paths the link argv accumulates.
    /// ld walks them in order to resolve `-l<name>` flags.
    pub library_paths: Vec<PathBuf>,
    /// `--wrap=<sym>` flags. ld redirects references to `<sym>` to
    /// `__wrap_<sym>` and renames the original definition to
    /// `__real_<sym>`. Prune *cannot* SHN_ABS-rewrite a reloc to a
    /// wrapped name because the post-wrap target is `__wrap_<sym>`,
    /// not the address of `<sym>` in base. We leave wrap-targeted
    /// relocs as UND symbol references and let ld handle them via
    /// the forwarded `--wrap` flag.
    pub wrapped: Vec<String>,
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
        // -l<name> / -l <name>: archive lookup. ld searches lib<name>.a
        // (and lib<name>.so) in -L paths + sysroot defaults.
        if a == "-l" {
            if let Some(v) = argv.get(i + 1) {
                out.libs.push(v.clone());
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("-l")
            && !v.is_empty()
            && !v.starts_with('-')
        {
            out.libs.push(v.to_string());
            i += 1;
            continue;
        }
        // -L<path> / -L <path>: library search path.
        if a == "-L" {
            if let Some(v) = argv.get(i + 1) {
                out.library_paths.push(PathBuf::from(v));
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("-L")
            && !v.is_empty()
        {
            out.library_paths.push(PathBuf::from(v));
            i += 1;
            continue;
        }
        // --wrap=<sym> / -Wl,--wrap=<sym> / -Wl,--wrap,<sym>
        if let Some(name) = extract_wrap(a, argv.get(i + 1).map(|s| s.as_str())) {
            out.wrapped.push(name.rhs.into_owned());
            i += if name.consumed_next { 2 } else { 1 };
            continue;
        }
        if is_input(a) {
            out.inputs.push(PathBuf::from(a));
        }
        i += 1;
    }
    out
}

/// The link argv's *flag surface*: every arg except the
/// classes whose effect the scan already captures by content —
///
///   - object-ish inputs (`is_input`): scanned and content-hashed;
///     their paths churn per build (rustc temp dirs, rlib metadata
///     hashes) while their content identity is what actually matters.
///   - `-o <path>`: graft owns and rewrites the output path.
///   - `-L <path>`: search paths only steer resolution; what the scan
///     hashes is the *resolved* archive's content.
///   - `-l<name>`: resolved archives enter the scan as deferred
///     inputs, so adding/removing one is an input change the closure
///     handles like any new rlib. (A `-l` resolving to a linker-script
///     stub is forwarded unscanned — but its *content* drift is
///     invisible to graft either way; the digest is a flag guard,
///     not a script-content guard.)
///
/// Everything else (`-Wl,*`, `-T`, `-u`, `--wrap`, `-static`,
/// `-nodefaultlibs`, `--ldproxy-*`, …) is retained IN ORDER: those are
/// link semantics graft cannot prove equivalent across a change. Base
/// records the list verbatim in the manifest (it's ~20 short strings);
/// overlay refuses on mismatch, naming the exact flags that changed
/// (auto converts the refusal into a full relink).
pub fn semantic_flags(argv: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = if argv.is_empty() { 0 } else { 1 };
    while i < argv.len() {
        let a = &argv[i];
        if is_input(a) {
            i += 1;
            continue;
        }
        // Two-token forms: skip flag + value. (Mirrors `parse`.)
        if a == "-o" || a == "-L" || a == "-l" {
            i += 2;
            continue;
        }
        // Attached forms.
        if a.len() > 2 && (a.starts_with("-o") || a.starts_with("-L")) {
            i += 1;
            continue;
        }
        if let Some(v) = a.strip_prefix("-l")
            && !v.is_empty()
            && !v.starts_with('-')
        {
            i += 1;
            continue;
        }
        out.push(a.clone());
        i += 1;
    }
    out
}

/// Human-readable difference between two flag surfaces, for the
/// overlay refusal message: flags added/removed (as multisets), or
/// "flag order changed" when the sets match and only order differs.
pub fn flag_surface_diff(base: &[String], cur: &[String]) -> String {
    let mut counts: std::collections::HashMap<&str, i64> = std::collections::HashMap::new();
    for f in cur {
        *counts.entry(f.as_str()).or_default() += 1;
    }
    for f in base {
        *counts.entry(f.as_str()).or_default() -= 1;
    }
    let mut added: Vec<&str> = Vec::new();
    let mut removed: Vec<&str> = Vec::new();
    for (f, n) in &counts {
        for _ in 0..(*n).max(0) {
            added.push(f);
        }
        for _ in 0..(-*n).max(0) {
            removed.push(f);
        }
    }
    added.sort_unstable();
    removed.sort_unstable();
    let mut parts = Vec::new();
    if !added.is_empty() {
        parts.push(format!("added: {}", added.join(" ")));
    }
    if !removed.is_empty() {
        parts.push(format!("removed: {}", removed.join(" ")));
    }
    if parts.is_empty() { "flag order changed".into() } else { parts.join("; ") }
}

/// Resolve a `-l<name>` flag to the archive path the linker would
/// pick. Walks `library_paths` in order, returning the first
/// `lib<name>.a` that exists. Falls back to the C compiler driver's
/// `-print-file-name=lib<name>.a` for archives that live in gcc's
/// own sysroot (libc, libm, libgcc, libstdc++ — not exposed via
/// argv `-L` flags). Returns `None` if neither finds a match.
pub fn resolve_lib(name: &str, library_paths: &[PathBuf]) -> Option<PathBuf> {
    for dir in library_paths {
        let candidate = dir.join(format!("lib{name}.a"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Like `resolve_lib`, but for archives in the C compiler's own
/// sysroot (libc / libgcc / libm / libstdc++). Falls through to
/// `<driver> -print-file-name=lib<name>.a`. The returned path
/// exists on disk; `None` means the driver couldn't resolve.
pub fn resolve_lib_via_driver(name: &str, driver: &Path) -> Option<PathBuf> {
    let out = std::process::Command::new(driver)
        .arg(format!("-print-file-name=lib{name}.a"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = std::str::from_utf8(&out.stdout).ok()?.trim();
    if line.is_empty() || line == format!("lib{name}.a") {
        // gcc echoes the input back when it can't find it.
        return None;
    }
    let p = PathBuf::from(line);
    p.is_file().then_some(p)
}

/// Pull the real-linker path out of the argv. Today this is the
/// `--ldproxy-linker <path>` arg ldproxy mode injects (esp-idf-sys
/// build script wires it in); future driver wrappers can be added
/// here. Falls back to `GRAFT_REAL_LD` env (default `cc`).
pub fn driver_path(argv: &[String]) -> PathBuf {
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == "--ldproxy-linker"
            && let Some(v) = argv.get(i + 1)
        {
            return PathBuf::from(v);
        }
        i += 1;
    }
    PathBuf::from(std::env::var("GRAFT_REAL_LD").unwrap_or_else(|_| "cc".into()))
}

struct Undefined<'a> {
    rhs: std::borrow::Cow<'a, str>,
    consumed_next: bool,
}

fn extract_wrap<'a>(cur: &'a str, _next: Option<&'a str>) -> Option<Undefined<'a>> {
    if let Some(s) = cur.strip_prefix("--wrap=") {
        return Some(Undefined { rhs: s.into(), consumed_next: false });
    }
    if let Some(rest) = cur.strip_prefix("-Wl,") {
        for tok in rest.split(',') {
            if let Some(s) = tok.strip_prefix("--wrap=") {
                return Some(Undefined { rhs: s.to_string().into(), consumed_next: false });
            }
        }
        // -Wl,--wrap,SYM
        let parts: Vec<&str> = rest.split(',').collect();
        let mut it = parts.iter().copied();
        while let Some(tok) = it.next() {
            if tok == "--wrap"
                && let Some(s) = it.next()
            {
                return Some(Undefined { rhs: s.to_string().into(), consumed_next: false });
            }
        }
    }
    None
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
/// EXCEPT:
///   - inputs (`is_input`): replaced by graft's pruned objects.
///   - `-o <out>`: replaced by overlay's own output path.
///   - `-l<name>` flags whose archive we've already expanded into the
///     scan + emitted as a filtered `.a` (in `stripped_libs`). Leaving
///     these in would cause ld to pull the original archive's full
///     contents alongside our pruned filtered version — duplicate
///     symbols, unresolved cross-archive references in code we
///     intended to drop.
///   - `-L<path>` library-search paths. With every `-l<name>` either
///     expanded into the scan or a known stub passed through verbatim,
///     ld no longer needs to search; we hand it concrete paths.
///
/// Stub `-l<name>` archives (linker scripts with `.a` extension, e.g.
/// `libesp_rom_sys.a`) are NOT in `stripped_libs` and therefore stay
/// forwarded — ld processes them as scripts, the same as a `-T` arg.
pub fn forwarded_link_args<'a>(
    argv: &'a [String],
    stripped_libs: &std::collections::HashSet<String>,
) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = if argv.is_empty() { 0 } else { 1 };
    while i < argv.len() {
        let a = &argv[i];
        if is_input(a) {
            i += 1;
            continue;
        }
        if a == "-o" {
            i += 2;
            continue;
        }
        if a.starts_with("-o") && a.len() > 2 {
            i += 1;
            continue;
        }
        // -l <name> / -l<name>
        if a == "-l" {
            if let Some(name) = argv.get(i + 1)
                && stripped_libs.contains(name)
            {
                i += 2;
                continue;
            }
        }
        if let Some(name) = a.strip_prefix("-l")
            && !name.is_empty()
            && !name.starts_with('-')
            && stripped_libs.contains(name)
        {
            i += 1;
            continue;
        }
        // Keep `-L` forwarded: ld also uses these paths to resolve
        // `-T <script>` linker-script names (e.g. esp-idf passes
        // `-T esp32s3.peripherals.ld -L .../soc/esp32s3/ld`). With every
        // walked `-l<name>` stripped above, archive search is moot;
        // the `-L`s only matter for script and stub-`-l` resolution.
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

    /// Content-covered argv classes (inputs, -o, -L, -l) must not
    /// perturb the flag surface: rustc churns those paths every build
    /// (temp dirs, rlib metadata hashes) — a surface that moved with
    /// them would rebase every incremental build.
    #[test]
    fn flag_surface_ignores_content_covered_classes() {
        let a = s(&[
            "cc", "-m64", "/tmp/rustcAAA/symbols.o", "/tmp/foo.rcgu.o",
            "-Wl,--as-needed", "/tmp/libbase-abc.rlib",
            "-L", "/tmp/native/aaa", "-L/tmp/native/bbb",
            "-lgcc_s", "-l", "util",
            "-o", "/tmp/out/app", "-nodefaultlibs",
        ]);
        let b = s(&[
            "cc", "-m64", "/tmp/rustcZZZ/symbols.o", "/tmp/foo2.rcgu.o",
            "-Wl,--as-needed", "/tmp/libbase-def.rlib", "/tmp/extra.rlib",
            "-L", "/tmp/native/ccc",
            "-lm", "-lgcc_s",
            "-o", "/tmp/elsewhere/app2", "-nodefaultlibs",
        ]);
        assert_eq!(semantic_flags(&a), semantic_flags(&b));
        assert_eq!(semantic_flags(&a), s(&["-m64", "-Wl,--as-needed", "-nodefaultlibs"]));
    }

    #[test]
    fn flag_surface_moves_on_flag_change_and_order() {
        let base = s(&["cc", "-m64", "-Wl,--as-needed", "-o", "/tmp/app", "/tmp/a.o"]);
        let added = s(&["cc", "-m64", "-Wl,--as-needed", "-Wl,--defsym=x=1", "-o", "/tmp/app", "/tmp/a.o"]);
        let removed = s(&["cc", "-m64", "-o", "/tmp/app", "/tmp/a.o"]);
        let reordered = s(&["cc", "-Wl,--as-needed", "-m64", "-o", "/tmp/app", "/tmp/a.o"]);
        let d = semantic_flags(&base);
        assert_ne!(d, semantic_flags(&added));
        assert_ne!(d, semantic_flags(&removed));
        assert_ne!(d, semantic_flags(&reordered));
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
