//! GNU ld `-Map` parsing: base mode's **address-recovery source**.
//!
//! base.elf's section headers only expose merged *output* sections, and
//! back-computing per-input addresses from symbols drifts the moment ld
//! relaxes a section (xtensa: deleted bytes shift every later symbol,
//! so `final − st_value` no longer points at the section start — the
//! reference-corpus link failure). The linker map states the placement fact
//! directly per input section — address, size, and the pre-relaxation
//! size — so base mode always asks the real linker for a map and builds
//! the section table from it.
//!
//! Self-verification is **byte matching**, not symbol cross-checks:
//! every attributed PROGBITS section's input bytes must reconcile with
//! base.elf's bytes at the map-claimed address (masked compare, with
//! the relaxation walk as the slow path on relaxing targets — see
//! `base::build_section_table`). A wrong or drifted parse places
//! sections at addresses whose bytes don't match, and the entry is
//! dropped (or, en masse, the build fails on zero attribution).
//!
//! Parse lines by token shape, never by substring: Rust v0-mangled
//! section names can contain a literal `"0x"` (`...10xtensa_cli...`),
//! which silently dropped 796 sections from the v1 relaxwalk corpus
//! (docs/16 §6.11).

/// One input-section line from the "Linker script and memory map" part
/// of a GNU ld map.
#[derive(Debug, Clone, PartialEq)]
pub struct MapSection {
    pub section: String,
    pub address: u64,
    /// Placed (post-relaxation) size.
    pub out_size: u64,
    /// Input size — differs from `out_size` only when ld annotated the
    /// record with "(size before relaxing)".
    pub in_size: u64,
    pub relaxed: bool,
    /// Object file basename and archive member, if any:
    /// `/path/libx.rlib(foo.o)` → (`libx.rlib`, `Some("foo.o")`).
    pub object: String,
    pub member: Option<String>,
    /// The path column verbatim (full path, member parens included) —
    /// for tools that need to reopen the file (relaxwalk).
    pub path: String,
}

/// Parse the input-section records of the "Linker script and memory
/// map" part of a GNU ld map. "Discarded input sections" (gc'd
/// content) and the memory-configuration tables are skipped. Handles
/// wrapped long section names and "(size before relaxing)" annotations
/// (xtensa).
pub fn parse_map(text: &str) -> Vec<MapSection> {
    let mut out: Vec<MapSection> = Vec::new();
    let mut in_map = false;
    // A long section name wraps onto its own line; the addr/size/path
    // tokens follow on the next line.
    let mut pending_name: Option<String> = None;
    // True only on the line right after a completed input-section
    // record — the only place a relax annotation may bind.
    let mut last_line_was_record = false;
    for line in text.lines() {
        if !in_map {
            if line.starts_with("Linker script and memory map") {
                in_map = true;
            }
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        // "(size before relaxing)" annotates the immediately preceding
        // input-section record with its input size.
        if line.trim_end().ends_with("(size before relaxing)") {
            if last_line_was_record
                && let (Some(last), Some(sz)) =
                    (out.last_mut(), toks.first().and_then(|t| hex(t)))
            {
                last.in_size = sz;
                last.relaxed = true;
            }
            pending_name = None;
            last_line_was_record = false;
            continue;
        }
        last_line_was_record = false;
        // Input-section lines are indented exactly one space and start
        // with the section name (` .text.foo …`). Output-section lines
        // start at column 0; symbol/assignment lines are indented
        // further.
        let named = line.starts_with(' ')
            && !line.starts_with("  ")
            && toks.first().is_some_and(|t| t.starts_with('.'));
        if named && toks.len() == 1 {
            pending_name = Some(toks[0].to_string());
            continue;
        }
        let (name, rest) = if named {
            (Some(toks[0].to_string()), &toks[1..])
        } else {
            (pending_name.take(), &toks[..])
        };
        pending_name = None;
        if let Some(name) = name {
            if let [a, s, path_toks @ ..] = rest
                && !path_toks.is_empty()
                && let (Some(address), Some(size)) = (hex(a), hex(s))
            {
                let path = path_toks.join(" "); // paths with spaces are rare but legal
                let (object, member) = split_member(&path);
                out.push(MapSection {
                    section: name,
                    address,
                    out_size: size,
                    in_size: size,
                    relaxed: false,
                    object,
                    member,
                    path,
                });
                last_line_was_record = true;
            }
        }
    }
    out
}

fn hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

/// `/path/libx.rlib(foo.o)` → (`libx.rlib`, Some(`foo.o`));
/// `/path/x.o` → (`x.o`, None). Basenames only — the map and the scan
/// can see the same file through different path spellings.
pub fn split_member(path: &str) -> (String, Option<String>) {
    let (file, member) = match path.split_once('(') {
        Some((f, m)) => (f, m.strip_suffix(')').map(|s| s.to_string())),
        None => (path, None),
    };
    let base = file.rsplit('/').next().unwrap_or(file).to_string();
    let member = member.map(|m| m.rsplit('/').next().unwrap_or(&m).to_string());
    (base, member)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
Discarded input sections

 .text.dead     0x0000000000000000       0x10 /tmp/app.o

Memory Configuration

Name             Origin             Length             Attributes

Linker script and memory map

LOAD /tmp/app.o

.text           0x0000000000401000     0x1000
 .text.foo      0x0000000000401000       0x24 /tmp/app.o
                0x0000000000401000                foo
 .text._ZN4very4long4name17h1234567890abcdefE
                0x0000000000401030       0x10 /tmp/libbase.rlib(base-xyz.rcgu.o)
 *fill*         0x0000000000401040        0x8
 .text._ZN3app10xtensa_cli3runE
                0x0000000000401050       0x4f /tmp/libbase.rlib(base-xyz.rcgu.o)
                                         0x5e (size before relaxing)
                0x0000000000401050                _stext = .
 .rodata.str1.1
                0x0000000000402000       0x15 /tmp/app.o
                0x0000000000401030                _ZN4very4long4name17h1234567890abcdefE
 *(.iram1 .iram1.*)
";

    #[test]
    fn parses_plain_wrapped_relaxed_and_member_lines() {
        let m = parse_map(SAMPLE);
        assert_eq!(m.len(), 4, "{m:?}");
        assert_eq!(m[0].section, ".text.foo");
        assert_eq!(m[0].address, 0x401000);
        assert_eq!(m[0].out_size, 0x24);
        assert_eq!(m[0].in_size, 0x24);
        assert!(!m[0].relaxed);
        assert_eq!(m[0].object, "app.o");
        assert_eq!(m[0].member, None);
        assert_eq!(m[1].section, ".text._ZN4very4long4name17h1234567890abcdefE");
        assert_eq!(m[1].address, 0x401030);
        assert_eq!(m[1].object, "libbase.rlib");
        assert_eq!(m[1].member.as_deref(), Some("base-xyz.rcgu.o"));
        // The "0x"-in-mangled-name landmine plus a relax annotation.
        assert_eq!(m[2].section, ".text._ZN3app10xtensa_cli3runE");
        assert_eq!(m[2].out_size, 0x4f);
        assert_eq!(m[2].in_size, 0x5e);
        assert!(m[2].relaxed);
        assert_eq!(m[3].section, ".rodata.str1.1");
        assert_eq!(m[3].address, 0x402000);
        // Symbol and assignment lines never parse as records.
        assert!(m.iter().all(|s| s.path.starts_with("/tmp/")));
    }

    #[test]
    fn discarded_sections_are_not_parsed() {
        let m = parse_map(SAMPLE);
        assert!(m.iter().all(|s| s.section != ".text.dead"));
    }
}
