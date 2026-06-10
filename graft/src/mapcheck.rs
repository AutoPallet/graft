//! `-Map` oracle: cross-check base's recovered section addresses against
//! the linker's own map file.
//!
//! `base::build_section_table` recovers each input section's placed
//! address by back-computing from symbols. The linker map states the
//! same fact directly (`<input section> <address> <size> <object>`), so
//! when `GRAFT_MAP_ORACLE=1` base mode asks the real linker for a map
//! and verifies every recovered address against it — ld is the
//! reference implementation, and any disagreement is an identity-model
//! bug that must fail the BASE build, not surface as a wrong-address
//! overlay at runtime. The oracle also reports *coverage gaps*: placed
//! sections the recovery couldn't pin (no usable symbols), which are
//! the inputs that would later produce "not found in base" bails.
//!
//! Enabled in the x86 e2e suite (and the xtensa dev loop) so the
//! oracle runs continuously without hardware.

use std::collections::HashMap;

use anyhow::{Result, bail};

use crate::scan::ScanResult;

/// One input-section line from the "Linker script and memory map" part
/// of a GNU ld map.
#[derive(Debug, PartialEq)]
pub struct MapSection {
    pub section: String,
    pub address: u64,
    pub size: u64,
    /// Object file name (basename) and archive member, if any:
    /// `/path/libx.rlib(foo.o)` → (`libx.rlib`, `Some("foo.o")`).
    pub object: String,
    pub member: Option<String>,
}

/// Parse the input-section lines of a GNU ld map. Only the
/// "Linker script and memory map" part is read — "Discarded input
/// sections" (gc'd content) and the memory-configuration tables are
/// skipped. Long section names wrap onto the next line; both forms are
/// handled.
pub fn parse_map(text: &str) -> Vec<MapSection> {
    let mut out = Vec::new();
    let mut in_map = false;
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if !in_map {
            if line.starts_with("Linker script and memory map") {
                in_map = true;
            }
            continue;
        }
        // Input-section lines are indented exactly one space and start
        // with the section name (` .text.foo …`). Output-section lines
        // start at column 0; symbol/assignment lines are indented
        // further and don't start with `.` after the leading spaces.
        let Some(rest) = line.strip_prefix(' ') else { continue };
        if !rest.starts_with('.') || rest.starts_with(". ") {
            continue;
        }
        if line.starts_with("  ") {
            continue; // deeper indentation: symbols, not section records
        }
        let mut tokens: Vec<&str> = rest.split_whitespace().collect();
        if tokens.len() == 1 {
            // Long name: `addr size object` wrapped onto the next line.
            let Some(next) = lines.peek() else { continue };
            let next_tokens: Vec<&str> = next.split_whitespace().collect();
            if next_tokens.len() >= 3 && next_tokens[0].starts_with("0x") {
                tokens.extend(next_tokens);
                lines.next();
            } else {
                continue;
            }
        }
        if tokens.len() < 4 {
            continue; // linker-script-generated section without an object
        }
        let (Some(address), Some(size)) = (parse_hex(tokens[1]), parse_hex(tokens[2])) else {
            continue;
        };
        let path = tokens[3..].join(" "); // paths with spaces are rare but legal
        let (object, member) = split_member(&path);
        out.push(MapSection {
            section: tokens[0].to_string(),
            address,
            size,
            object,
            member,
        });
    }
    out
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x")?;
    u64::from_str_radix(s, 16).ok()
}

/// `/path/libx.rlib(foo.o)` → (`libx.rlib`, Some(`foo.o`));
/// `/path/x.o` → (`x.o`, None). Basenames only — the map and the scan
/// can see the same file through different path spellings.
fn split_member(path: &str) -> (String, Option<String>) {
    let (file, member) = match path.split_once('(') {
        Some((f, m)) => (f, m.strip_suffix(')').map(|s| s.to_string())),
        None => (path, None),
    };
    let base = file.rsplit('/').next().unwrap_or(file).to_string();
    let member = member.map(|m| m.rsplit('/').next().unwrap_or(&m).to_string());
    (base, member)
}

pub struct OracleStats {
    pub checked: usize,
    pub skipped_ambiguous_key: usize,
    pub coverage_gaps: usize,
}

/// Verify every recovered per-node address against the map, and count
/// placed sections the recovery has no entry for. `node_addrs` is the
/// per-node recovery result from `base::build_section_table` (before
/// the trans_hash collapse, so ambiguous-hash copies are individually
/// checkable). Returns stats; bails on any address mismatch.
pub fn oracle_check(
    scan: &ScanResult,
    node_addrs: &HashMap<u32, u64>,
    map: &[MapSection],
) -> Result<OracleStats> {
    if map.is_empty() {
        bail!(
            "map oracle: parsed zero input-section records — wrong linker \
             map format (is the real linker GNU ld?)"
        );
    }
    // (object basename, member, section name) → addresses. A key
    // appearing at several addresses (same-named section twice in one
    // object) can't be attributed to a specific node — skip those.
    let mut index: HashMap<(String, Option<String>, String), Vec<u64>> = HashMap::new();
    for m in map {
        index
            .entry((m.object.clone(), m.member.clone(), m.section.clone()))
            .or_default()
            .push(m.address);
    }

    let mut mismatches: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut skipped_ambiguous_key = 0usize;
    let mut gaps = 0usize;
    for (nid, nm) in scan.graph.nodes.iter().enumerate() {
        if nm.is_aggregator() {
            continue; // many contributors, no single base address
        }
        let [seg] = nm.segments.as_slice() else { continue };
        if seg.range.is_some() {
            // Per-string node: ld shuffles merged strings, so the
            // input section's map address says nothing about where a
            // specific string landed.
            continue;
        }
        let obj = &scan.objects[seg.object as usize];
        let sec = &obj.sections[seg.section as usize];
        let input = &scan.inputs[seg.object as usize];
        let obj_name = input
            .source_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let key = (obj_name, input.member_name.clone(), sec.name.clone());
        let Some(addrs) = index.get(&key) else {
            continue; // gc'd by ld, or a non-alloc section — nothing to check
        };
        if addrs.len() > 1 {
            skipped_ambiguous_key += 1;
            continue;
        }
        match node_addrs.get(&(nid as u32)) {
            Some(&recovered) => {
                checked += 1;
                if recovered != addrs[0] {
                    mismatches.push(format!(
                        "  {} :: {} — recovered {recovered:#x}, map says {:#x}",
                        input.label(),
                        sec.name,
                        addrs[0],
                    ));
                }
            }
            None => {
                // ld placed it; recovery couldn't pin it. Not an error
                // (it may never be referenced), but it's exactly the
                // population that produces "not found in base" bails.
                if sec.bytes.len() as u64 > 0 || addrs[0] != 0 {
                    gaps += 1;
                }
            }
        }
    }
    if !mismatches.is_empty() {
        bail!(
            "graft base map-oracle: {} recovered address(es) disagree with the \
             linker map:\n{}",
            mismatches.len(),
            mismatches.join("\n"),
        );
    }
    if checked == 0 {
        bail!(
            "map oracle: zero recovered addresses matched a map record — \
             object/section key derivation is broken"
        );
    }
    Ok(OracleStats { checked, skipped_ambiguous_key, coverage_gaps: gaps })
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

.text           0x0000000000401000     0x1000
 .text.foo      0x0000000000401000       0x24 /tmp/app.o
 .text._ZN4very4long4name17h1234567890abcdefE
                0x0000000000401030       0x10 /tmp/libbase.rlib(base-xyz.rcgu.o)
 *fill*         0x0000000000401040        0x8
 .rodata.str1.1
                0x0000000000402000       0x15 /tmp/app.o
                0x0000000000401030                _ZN4very4long4name17h1234567890abcdefE
";

    #[test]
    fn parses_plain_wrapped_and_member_lines() {
        let secs = parse_map(SAMPLE);
        assert_eq!(secs.len(), 3, "{secs:?}");
        assert_eq!(secs[0].section, ".text.foo");
        assert_eq!(secs[0].address, 0x401000);
        assert_eq!(secs[0].object, "app.o");
        assert_eq!(secs[0].member, None);
        assert_eq!(secs[1].section, ".text._ZN4very4long4name17h1234567890abcdefE");
        assert_eq!(secs[1].address, 0x401030);
        assert_eq!(secs[1].object, "libbase.rlib");
        assert_eq!(secs[1].member.as_deref(), Some("base-xyz.rcgu.o"));
        assert_eq!(secs[2].section, ".rodata.str1.1");
        assert_eq!(secs[2].address, 0x402000);
    }

    #[test]
    fn discarded_sections_are_not_parsed() {
        let secs = parse_map(SAMPLE);
        assert!(secs.iter().all(|s| s.section != ".text.dead"));
    }
}
