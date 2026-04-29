//! Synthesize phantom graph nodes for linker-aggregated outputs whose
//! *bracket symbols* code references via reloc — `__init_array_start`
//! / `__init_array_end` and the parallel `.fini_array` /
//! `.preinit_array` pairs.
//!
//! These outputs are produced by ld merging many input contributions
//! (`.init_array.*` from each `.o`); the bracket symbols are
//! linker-script-defined and bracket the merged output. C runtime
//! startup walks `[__init_array_start, __init_array_end)` to call
//! constructors. Without synthesis, refs to the bracket symbols find
//! no defined-symbol in any input `.o` → prune bails. With synthesis,
//! a phantom node owns the bracket symbols, its successors are the
//! contributing inputs, and trans_hash propagation cascades any
//! contributor change up to the constructor-walking loop.
//!
//! Other linker-aggregated outputs (PT_NOTE, `.eh_frame*`, plain
//! `.ctors`/`.dtors` without bracket symbols) don't earn synthesis:
//! they're consumed at runtime via segment headers / linker-script
//! brackets, and *no code reloc references them*. We just stop
//! rooting them — overlay's prune drops the contributors, ld at
//! overlay link time pulls nothing into the merged output, and
//! combined ELF runs on base's copies. ld is still responsible for
//! actually emitting these sections; graft only models dependency
//! propagation, not output emission.

/// One catalog entry per linker-aggregated output where graft needs
/// dependency-propagation modeling.
pub struct Aggregator {
    /// Stable identifier (matches the merged-output section name).
    pub id: &'static str,
    /// How to identify input sections that contribute to this output.
    pub contributor: Contributor,
    /// Real linker-script-defined bracket symbols. Their addresses
    /// live in base.elf's `.symtab`; refs from code resolve through
    /// the normal symhash machinery once the phantom node is in the
    /// graph.
    pub bracket_symbols: &'static [BracketSymbol],
}

/// Predicate for "is this input section a contributor to that
/// aggregator?" Matched against `ParsedSection::name`.
pub enum Contributor {
    /// Exact name OR `<name>.<anything>` — covers ld's
    /// `KEEP(*(.init_array .init_array.*))` idiom.
    ExactOrDot(&'static str),
}

impl Contributor {
    pub fn matches(&self, name: &str) -> bool {
        match self {
            Contributor::ExactOrDot(p) => {
                name == *p
                    || name
                        .strip_prefix(p)
                        .is_some_and(|rest| rest.starts_with('.'))
            }
        }
    }
}

pub struct BracketSymbol {
    pub name: &'static str,
    pub end: BracketEnd,
}

#[derive(Clone, Copy)]
pub enum BracketEnd {
    /// Symbol's offset within the merged output is 0.
    Start,
    /// Symbol's offset within the merged output is `total_size`.
    End,
}

pub const AGGREGATORS: &[Aggregator] = &[
    Aggregator {
        id: ".init_array",
        contributor: Contributor::ExactOrDot(".init_array"),
        bracket_symbols: &[
            BracketSymbol { name: "__init_array_start", end: BracketEnd::Start },
            BracketSymbol { name: "__init_array_end",   end: BracketEnd::End },
        ],
    },
    Aggregator {
        id: ".fini_array",
        contributor: Contributor::ExactOrDot(".fini_array"),
        bracket_symbols: &[
            BracketSymbol { name: "__fini_array_start", end: BracketEnd::Start },
            BracketSymbol { name: "__fini_array_end",   end: BracketEnd::End },
        ],
    },
    Aggregator {
        id: ".preinit_array",
        contributor: Contributor::ExactOrDot(".preinit_array"),
        bracket_symbols: &[
            BracketSymbol { name: "__preinit_array_start", end: BracketEnd::Start },
            BracketSymbol { name: "__preinit_array_end",   end: BracketEnd::End },
        ],
    },
];

/// Returns the aggregator a given input section name contributes to,
/// if any.
pub fn aggregator_for_section(name: &str) -> Option<&'static Aggregator> {
    AGGREGATORS.iter().find(|a| a.contributor.matches(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_array_contributor_match() {
        let a = aggregator_for_section(".init_array").unwrap();
        assert_eq!(a.id, ".init_array");
        let a = aggregator_for_section(".init_array.65535").unwrap();
        assert_eq!(a.id, ".init_array");
        // ".init" doesn't match the .init_array prefix idiom.
        assert!(aggregator_for_section(".init").is_none());
    }

    #[test]
    fn ordinary_text_section_is_not_a_contributor() {
        assert!(aggregator_for_section(".text").is_none());
        assert!(aggregator_for_section(".text._ZN3foo3bar17h0123456789abcdefE").is_none());
    }

    #[test]
    fn note_and_eh_frame_are_not_aggregators() {
        // We deliberately don't synthesize for these — they're
        // consumed via segment headers, no code reloc references
        // them, and dropping their roots in overlay mode is enough.
        assert!(aggregator_for_section(".note.gnu.property").is_none());
        assert!(aggregator_for_section(".eh_frame").is_none());
    }
}
