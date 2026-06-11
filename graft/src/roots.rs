//! Compute the gc-sections root set — the nodes the overlay closure
//! walk must start from.
//!
//! This mirrors ld's rules for what's "always kept" regardless of
//! reachability. For x86-linux with no custom script (rustc's default
//! config), we enumerate the built-in ELF script's KEEP() patterns
//! plus anything ld picks up from argv or section flags. Supporting a
//! user-supplied linker script (esp-idf on M1) is a natural extension
//! — parse the script, pull KEEP() patterns out of its SECTIONS block,
//! and merge them into `WELL_KNOWN_KEEP_PATTERNS`.
//!
//! Root rules, in the order ld would apply them:
//!
//!   1. Entry symbol. `manifest.entry_symbol` names it (M0.5: always
//!      `main`). On a hosted link the *real* ld entry is `_start` (in
//!      crt1.o, outside our scan), but `_start` immediately calls
//!      `main` — treating main as the root covers the same reach-cone
//!      from our graph's perspective.
//!
//!   2. `-u SYM` / `--undefined SYM` on argv. Force-undefined symbols.
//!
//!   3. SHF_GNU_RETAIN (the `R` section flag). rustc stamps this on
//!      sections holding `#[used]` / `#[unsafe(link_section = ...)]`
//!      statics and any user-facing "don't gc me" cue.
//!
//!   4. Well-known KEEP() patterns from ld's default script:
//!      .init / .fini, .init_array*, .fini_array*, .preinit_array*,
//!      .jcr, .note.*.
//!
//! `.eh_frame` / `.gcc_except_table` are deliberately *not* treated as
//! roots here. ld keeps them, but its gc-sections prunes FDEs whose
//! target `.text` was discarded. Our closure walks forward reloc edges,
//! so treating `.eh_frame` as a root would pull in every `.text.*` it
//! FDE-covers — effectively the entire program. Overlay unwind is a
//! deferred gap anyway (no runtime `__register_frame`); base owns its
//! own unwind tables. If a richer unwind story lands, the right fix is
//! per-FDE splitting inside prune, not root admission here.

use std::collections::BTreeSet;

use anyhow::Result;

use crate::argv::LinkArgs;
use crate::graph::NodeId;
use crate::overlay::BaseMetadata;
use crate::scan::ScanResult;

/// ELF section-flag bits we care about. Not in `object::elf` as named
/// constants in older versions, so re-declared here.
const SHF_GNU_RETAIN: u64 = 0x00200000;

/// Section-name prefixes and exact matches ld's built-in ELF script
/// puts under `KEEP()`. Matching any of these makes a scan-visible
/// section a root.
///
/// Sourced from `ld --verbose` on x86_64-linux (binutils 2.40-ish).
/// The patterns that matter for rustc output are a subset — e.g.,
/// `.jcr` and SunOS handoffs never appear — but we keep them for
/// fidelity with what ld would have done on the same inputs.
///
/// **Aggregated outputs we model as synthetic phantoms** (`.init_array`,
/// `.fini_array`, `.preinit_array`) are *not* listed here: their
/// contributors get reached via the synthetic node's edges, and the
/// synthetic node is reached from code via reloc to bracket symbols
/// (`__init_array_start` etc.). See `synthetic.rs`.
///
/// **Aggregated outputs without bracket symbols** (`.note.*`,
/// `.eh_frame*`, plain `.ctors`/`.dtors`, `.init`/`.fini` function-
/// body slivers from gcc startup files) are also not listed here:
/// they're consumed at runtime via segment headers (PT_NOTE,
/// PT_GNU_EH_FRAME) or via real symbols that point at the merged
/// output (`_init`, `_fini` — defined in crti.o, classified
/// normally). Individual contributor slivers without their own
/// defined symbols would never classify as Provided and would
/// always Include into the closure for no payoff. No code reloc
/// reaches them, so without rooting they fall out of the closure
/// entirely; ld at overlay link time won't see contributors in
/// the pruned input set, and the combined ELF runs on base's
/// copies.
const WELL_KNOWN_KEEP_PATTERNS: &[KeepPattern] = &[
    KeepPattern::Exact(".jcr"),
];

enum KeepPattern {
    /// Exact match, e.g. `.init`.
    Exact(&'static str),
    /// Exact match OR `<name>.<anything>` — covers ld's
    /// `KEEP(*(.init_array .init_array.*))` idiom. Currently unused
    /// in `WELL_KNOWN_KEEP_PATTERNS` (the prefix-style aggregations
    /// migrated to `synthetic.rs` for `.init_array`-class outputs,
    /// or dropped from rooting entirely for `.note.*`-class). Kept
    /// available for re-introducing patterns when new ones surface.
    #[allow(dead_code)]
    ExactOrDot(&'static str),
}

impl KeepPattern {
    fn matches(&self, name: &str) -> bool {
        match self {
            KeepPattern::Exact(p) => name == *p,
            KeepPattern::ExactOrDot(p) => {
                name == *p
                    || name
                        .strip_prefix(p)
                        .is_some_and(|rest| rest.starts_with('.'))
            }
        }
    }
}

pub fn find_roots(
    scan: &ScanResult,
    base: &BaseMetadata,
    link_args: &LinkArgs,
) -> Result<Vec<NodeId>> {
    let mut roots: BTreeSet<NodeId> = BTreeSet::new();

    // (1) Entry symbol.
    let entry = base.manifest.entry_symbol.as_str();
    if let Some((nid, _)) = scan.graph.symbols.resolve_global(entry) {
        roots.insert(nid);
    }
    // Note: it's valid for the entry to not resolve in overlay's inputs
    // if the scan didn't see main's .o (dead-code closure rebuilds).
    // Not an error — just means no main-root, other roots may still fire.

    // (2) -u / --undefined from argv.
    for sym in &link_args.undefined {
        if let Some((nid, _)) = scan.graph.symbols.resolve_global(sym) {
            roots.insert(nid);
        }
    }

    // (3) + (4): per-segment retain / well-known-keep checks. Any
    // segment with SHF_GNU_RETAIN or a well-known-keep name makes the
    // whole node a root — segments of one node travel together, so
    // retain-on-one is retain-on-all. (For aggregator nodes, this
    // also handles cases like base linker scripts retaining
    // `.init_array.*`.)
    for nid in 0..scan.graph.nodes.len() as NodeId {
        let nm = &scan.graph.nodes[nid as usize];
        let any_retain_or_keep = nm.segments.iter().any(|seg| {
            let sec = &scan.objects[seg.object as usize].sections[seg.section as usize];
            sec.sh_flags & SHF_GNU_RETAIN != 0
                || WELL_KNOWN_KEEP_PATTERNS.iter().any(|p| p.matches(&sec.name))
        });
        if any_retain_or_keep {
            roots.insert(nid);
        }
    }

    Ok(roots.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_pattern_exact() {
        let p = KeepPattern::Exact(".init");
        assert!(p.matches(".init"));
        assert!(!p.matches(".init_array"));
        assert!(!p.matches(".init.something"));
    }

    #[test]
    fn keep_pattern_exact_or_dot() {
        let p = KeepPattern::ExactOrDot(".init_array");
        assert!(p.matches(".init_array"));
        assert!(p.matches(".init_array.65535"));
        assert!(p.matches(".init_array.somelabel"));
        // Not a prefix match — `.init_array2` shouldn't match.
        assert!(!p.matches(".init_array2"));
        // Not a substring match either.
        assert!(!p.matches("prefix.init_array"));
    }
}
