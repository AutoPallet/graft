//! Parse the argv rustc hands us. We only care about three things:
//! the output path, the set of object-ish inputs (`.o`, `.rcgu.o`,
//! `.rlib`, `.a`), and everything else (passed through untouched when
//! we exec the real linker).

use std::path::{Path, PathBuf};

/// Inputs and archive-group delimiters in linker command-line order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkInput {
    Path(PathBuf),
    Library(String),
    StartGroup,
    EndGroup,
}

#[derive(Debug, Default, Clone)]
pub struct LinkArgs {
    pub inputs: Vec<PathBuf>,
    pub ordered_inputs: Vec<LinkInput>,
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
    /// True if the argv carries `--whole-archive` (or
    /// `--no-whole-archive`) in any spelling. ld's whole-archive mode
    /// force-loads every member of the bracketed archives regardless of
    /// reference — a loading model the scan doesn't implement (members
    /// with no inbound strong ref would be invisible to the graph and
    /// the boot fingerprint). base/overlay refuse when this is set.
    pub whole_archive: bool,
}

pub fn parse(argv: &[String]) -> LinkArgs {
    // Normalize linker-driver spellings before interpreting order-sensitive
    // inputs. Keep the original argv for forwarding to the compiler driver.
    let argv: Vec<String> = argv.iter().enumerate().flat_map(|(i, arg)| {
        if i != 0 && let Some(flags) = arg.strip_prefix("-Wl,") {
            flags.split(',').map(str::to_owned).collect()
        } else {
            vec![arg.clone()]
        }
    }).collect();
    let mut out = LinkArgs::default();
    let mut i = 0;
    // argv[0] is graft itself when invoked as a command, or the linker
    // path when rustc passes argv — skip it either way by starting from 1.
    if argv.len() > 0 {
        i = 1;
    }
    while i < argv.len() {
        let a = &argv[i];
        if matches!(a.as_str(), "--start-group" | "-(" | "--end-group" | "-)") {
            out.ordered_inputs.push(if matches!(a.as_str(), "--start-group" | "-(") {
                LinkInput::StartGroup
            } else {
                LinkInput::EndGroup
            });
            i += 1;
            continue;
        }
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
                out.ordered_inputs.push(LinkInput::Library(v.clone()));
                i += 2;
                continue;
            }
        }
        if let Some(v) = a.strip_prefix("-l")
            && !v.is_empty()
            && !v.starts_with('-')
        {
            out.libs.push(v.to_string());
            out.ordered_inputs.push(LinkInput::Library(v.to_string()));
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
        // Any spelling of --whole-archive / --no-whole-archive (bare,
        // -Wl,-wrapped, comma-joined). Substring match is safe: no
        // other ld flag contains "whole-archive".
        if a.contains("whole-archive") {
            out.whole_archive = true;
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
            out.ordered_inputs.push(LinkInput::Path(PathBuf::from(a)));
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
        // GCC's LTO plugin writes this scratch file during linking. Its random
        // filename is an output location, not a semantic input.
        if a.starts_with("-plugin-opt=-fresolution=") {
            out.push("-plugin-opt=-fresolution=<link-output>".into());
            i += 1;
            continue;
        }
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

/// Resolve a library against the effective linker search paths supplied by the
/// compiler driver. Driver specs and multilib choices must already be expanded.
pub fn resolve_lib(name: &str, library_paths: &[PathBuf]) -> Option<PathBuf> {
    for dir in library_paths {
        let candidate = dir.join(format!("lib{name}.a"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
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

/// Ask the compiler driver to expand response files, specs and multilib options
/// without executing the linker. This supplies the same ordered inputs and
/// library search paths that the real link will use.
pub fn driver_link_argv(argv: &[String], driver: &Path) -> anyhow::Result<Vec<String>> {
    use anyhow::{Context, bail};
    // With an @file on its command line, GCC can hide inputs in a temporary
    // response file that is deleted before -### returns.
    let argv = expand_response_files(argv)?;
    let mut command = std::process::Command::new(driver);
    let mut index = 1;
    while index < argv.len() {
        if matches!(argv[index].as_str(), "--ldproxy-linker" | "--ldproxy-cwd") {
            index += 2;
            continue;
        }
        command.arg(&argv[index]);
        index += 1;
    }
    let output = command.arg("-###").output()
        .with_context(|| format!("query linker command from {}", driver.display()))?;
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        bail!("compiler driver query failed: {diagnostic}");
    }
    for line in diagnostic.lines().rev() {
        let Some(args) = shlex::split(line) else { continue; };
        let Some(program) = args.first() else { continue; };
        let name = Path::new(program).file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name == "collect2" || name == "ld" || name.starts_with("ld.") || name.ends_with("-ld") {
            return expand_response_files(&args);
        }
    }
    bail!("compiler driver did not report a linker command: {diagnostic}")
}

/// Expand nested GNU response files before scanning or rewriting inputs.
/// Relative paths are resolved against the linker's working directory.
pub fn expand_response_files(argv: &[String]) -> anyhow::Result<Vec<String>> {
    use anyhow::{Context, bail};
    let mut args = argv.to_vec();
    let mut index = 1;
    let mut expanded = 0;
    while index < args.len() {
        let Some(path) = args[index].strip_prefix('@') else {
            index += 1;
            continue;
        };
        expanded += 1;
        if expanded > 2000 { bail!("too many nested response files"); }
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("read linker response file {path}"))?;
        let tokens = response_tokens(&contents)
            .with_context(|| format!("parse linker response file {path}"))?;
        args.splice(index..=index, tokens);
    }
    Ok(args)
}

fn response_tokens(contents: &str) -> anyhow::Result<Vec<String>> {
    use anyhow::bail;
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = contents.chars();
    while let Some(c) = chars.next() {
        if c == '\0' { bail!("NUL in response file"); }
        if c == '\\' {
            // GCC versions disagree on backslashes inside quotes and escaped
            // newlines. Refuse these forms instead of changing their meaning.
            if quote.is_some() { bail!("backslash inside quoted response-file argument is unsupported"); }
            let escaped = chars.next().ok_or_else(|| anyhow::anyhow!("trailing response-file backslash"))?;
            if matches!(escaped, '\n' | '\r' | '\0') { bail!("escaped newline or NUL in response file is unsupported"); }
            token.push(escaped);
            started = true;
        } else if quote == Some(c) {
            quote = None;
        } else if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
            started = true;
        } else if quote.is_none() && c.is_ascii_whitespace() {
            if started { tokens.push(std::mem::take(&mut token)); }
            started = false;
        } else {
            token.push(c);
            started = true;
        }
    }
    if quote.is_some() { bail!("unterminated quote in response file"); }
    if started { tokens.push(token); }
    Ok(tokens)
}

struct Undefined<'a> {
    rhs: std::borrow::Cow<'a, str>,
    consumed_next: bool,
}

fn extract_wrap<'a>(cur: &'a str, next: Option<&'a str>) -> Option<Undefined<'a>> {
    if cur == "--wrap" {
        return next.map(|s| Undefined { rhs: s.into(), consumed_next: true });
    }
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
pub fn forwarded_link_args(
    argv: &[String],
    stripped_libs: &std::collections::HashSet<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = if argv.is_empty() { 0 } else { 1 };
    while i < argv.len() {
        let a = &argv[i];
        if let Some(flags) = a.strip_prefix("-Wl,") {
            let nested: Vec<_> = std::iter::once("ld".to_owned())
                .chain(flags.split(',').map(str::to_owned)).collect();
            let kept = forwarded_link_args(&nested, stripped_libs);
            if !kept.is_empty() { out.push(format!("-Wl,{}", kept.join(","))); }
            i += 1;
            continue;
        }
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
        out.push(a.clone());
        i += 1;
    }
    out
}

/// blake3 content hashes of every `-T` / `--script` linker script on
/// the argv, resolved the way ld does (path as given, else searched in
/// `-L` paths), sorted for order-independence. The v11 flag guard
/// records the script's *name*; this closes the in-place-edit hole
/// (editing memory.x without renaming it changes PROVIDE/KEEP/placement
/// semantics invisibly to both the flag surface and the content
/// hashes). A name that doesn't resolve to a readable file hashes as a
/// marker over the name itself — ld's own script search may still find
/// it, but a swap of which file the name resolves to is exactly a `-L`
/// change, which the resolved-content hash captures.
///
/// Limitation: `INCLUDE`d sub-scripts are not chased; editing one
/// without touching its includer stays invisible.
pub fn script_content_hashes(argv: &[String], library_paths: &[PathBuf]) -> Vec<[u8; 32]> {
    // Flatten -Wl, aggregates so `-Wl,-T,foo.ld` parses like `-T foo.ld`.
    let mut toks: Vec<String> = Vec::new();
    for a in argv.iter().skip(1) {
        if let Some(rest) = a.strip_prefix("-Wl,") {
            toks.extend(rest.split(',').map(str::to_string));
        } else {
            toks.push(a.clone());
        }
    }
    let mut names: Vec<String> = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        let t = &toks[i];
        if t == "-T" || t == "--script" {
            if let Some(n) = toks.get(i + 1) {
                names.push(n.clone());
                i += 2;
                continue;
            }
        } else if let Some(n) = t.strip_prefix("--script=") {
            names.push(n.to_string());
        } else if let Some(n) = t.strip_prefix("-T")
            && !n.is_empty()
        {
            names.push(n.to_string());
        }
        i += 1;
    }
    let mut hashes: Vec<[u8; 32]> = names
        .iter()
        .map(|n| {
            let direct = Path::new(n);
            let content = if direct.is_file() {
                std::fs::read(direct).ok()
            } else {
                library_paths
                    .iter()
                    .map(|d| d.join(n))
                    .find(|c| c.is_file())
                    .and_then(|c| std::fs::read(&c).ok())
            };
            match content {
                Some(bytes) => *blake3::hash(&bytes).as_bytes(),
                None => *blake3::hash(format!("<unresolved-script:{n}>").as_bytes()).as_bytes(),
            }
        })
        .collect();
    hashes.sort_unstable();
    hashes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> { v.iter().map(|x| x.to_string()).collect() }

    #[test]
    fn script_hashes_catch_in_place_edits() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("memory.x");
        std::fs::write(&script, "PROVIDE(x = 1);").unwrap();
        let argv = s(&["ld", "-T", script.to_str().unwrap(), "-o", "/tmp/out"]);
        let before = script_content_hashes(&argv, &[]);
        assert_eq!(before.len(), 1);
        // Same argv, edited content → different hash.
        std::fs::write(&script, "PROVIDE(x = 2);").unwrap();
        assert_ne!(before, script_content_hashes(&argv, &[]));
    }

    #[test]
    fn script_hashes_resolve_via_library_paths_and_wl() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("periph.ld"), "MEMORY {}").unwrap();
        let argv = s(&["ld", "-Wl,-T,periph.ld", "-o", "/tmp/out"]);
        let resolved = script_content_hashes(&argv, &[dir.path().to_path_buf()]);
        let unresolved = script_content_hashes(&argv, &[]);
        assert_eq!(resolved.len(), 1);
        assert_ne!(resolved, unresolved, "resolution state must be visible");
        // -T<attached> spelling matches the two-token spelling.
        let attached = s(&["ld", &format!("-T{}", dir.path().join("periph.ld").display())]);
        assert_eq!(resolved, script_content_hashes(&attached, &[]));
    }

    #[test]
    fn preserves_paths_libraries_repeats_and_groups_in_order() {
        use LinkInput::*;
        let args = parse(&s(&["cc", "main.o", "first.a", "-l", "middle",
            "-Wl,--start-group,-llast,first.a,--end-group", "-lmiddle"]));
        assert_eq!(args.ordered_inputs, vec![Path("main.o".into()), Path("first.a".into()),
            Library("middle".into()), StartGroup, Library("last".into()),
            Path("first.a".into()), EndGroup, Library("middle".into())]);
    }

    #[test]
    fn parses_multiple_wrapped_roots_and_wraps() {
        let args = parse(&s(&["cc", "-Wl,-u,first,--undefined=second,--wrap,rand,--wrap=other"]));
        assert_eq!(args.undefined, s(&["first", "second"]));
        assert_eq!(args.wrapped, s(&["rand", "other"]));
    }

    #[test]
    fn forwarding_removes_scanned_inputs_inside_driver_flags() {
        let args = s(&["cc", "main.o", "-Wl,--start-group,-lfirst,other.a,-lstub,--end-group", "-o", "app"]);
        let stripped = std::collections::HashSet::from(["first".to_owned()]);
        assert_eq!(forwarded_link_args(&args, &stripped), s(&["-Wl,--start-group,-lstub,--end-group"]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn compiler_specs_and_response_files_select_library_search_paths() {
        let dir = tempfile::tempdir().unwrap();
        let selected = dir.path().join("selected");
        std::fs::create_dir(&selected).unwrap();
        std::fs::write(selected.join("libchoice.a"), b"").unwrap();
        let specs = dir.path().join("selection.specs");
        std::fs::write(&specs, format!("%rename link original_link\n*link:\n-L{} %(original_link)\n", selected.display())).unwrap();
        let response = dir.path().join("flags with spaces");
        std::fs::write(&response, format!("\"-specs={}\" -nostdlib -lchoice", specs.display())).unwrap();
        let output = dir.path().join("must_not_be_created");
        let args = vec!["graft".into(), "--ldproxy-linker".into(), "gcc".into(),
            "--ldproxy-cwd".into(), dir.path().display().to_string(),
            format!("@{}", response.display()), "missing.o".into(),
            "-o".into(), output.display().to_string()];
        let expanded = driver_link_argv(&args, Path::new("gcc")).unwrap();
        let parsed = parse(&expanded);
        assert_eq!(resolve_lib("choice", &parsed.library_paths), Some(selected.join("libchoice.a")));
        assert!(parsed.libs.contains(&"choice".to_owned()));
        assert!(!output.exists(), "driver query must not execute the linker");
        let before = semantic_flags(&expanded);
        let repeated = driver_link_argv(&args, Path::new("gcc")).unwrap();
        assert_eq!(before, semantic_flags(&repeated), "compiler scratch paths must not invalidate the base");
        std::fs::write(&response, format!("\"-specs={}\" -nostdlib -lchoice -Wl,--defsym=changed=1", specs.display())).unwrap();
        let after = driver_link_argv(&args, Path::new("gcc")).unwrap();
        assert_ne!(before, semantic_flags(&after), "response-file flag edits must invalidate the base");
    }

    #[test]
    fn response_file_quoting_and_nesting() {
        assert_eq!(response_tokens("'two words' escaped\\ space #literal \"\" plain").unwrap(),
            s(&["two words", "escaped space", "#literal", "", "plain"]));
        assert!(response_tokens("'ambiguous\\quote'").is_err());
        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("inner");
        let outer = dir.path().join("outer");
        std::fs::write(&inner, "-lfirst main.o").unwrap();
        std::fs::write(&outer, format!("@{} -lsecond", inner.display())).unwrap();
        assert_eq!(expand_response_files(&s(&["cc", &format!("@{}", outer.display())])).unwrap(),
            s(&["cc", "-lfirst", "main.o", "-lsecond"]));
        std::fs::write(&inner, format!("@{}", outer.display())).unwrap();
        assert!(expand_response_files(&s(&["cc", &format!("@{}", outer.display())])).is_err());
    }

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

    #[test]
    fn whole_archive_any_spelling_is_flagged() {
        for flag in [
            "--whole-archive",
            "--no-whole-archive",
            "-Wl,--whole-archive",
            "-Wl,--whole-archive,--no-whole-archive",
        ] {
            let argv = s(&["ld", flag, "-o", "/tmp/out", "/tmp/foo.o"]);
            let parsed = parse(&argv);
            assert!(parsed.whole_archive, "{flag} not detected");
            // The flag must not eat neighbors: inputs still parsed.
            assert_eq!(parsed.inputs.len(), 1, "{flag}");
        }
        let argv = s(&["ld", "-o", "/tmp/out", "/tmp/foo.o"]);
        assert!(!parse(&argv).whole_archive);
    }
}
