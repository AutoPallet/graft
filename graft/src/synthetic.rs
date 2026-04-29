//! Synthesize phantom graph nodes for *aggregated* linker outputs:
//! sections / segments base.elf produces by merging many input
//! contributions, where the runtime consumes the merged result as a
//! single unit (either by symbol — `__init_array_start`/`end` brackets
//! — or by program header — `PT_NOTE`, `PT_GNU_EH_FRAME`).
//!
//! Without synthesis, individual contributors (`.init_array.65535`,
//! `.note.gnu.property` from each `.o`) end up as roots via ld's
//! KEEP-pattern model, which rules our `find_roots`. They have no
//! defined named symbols, so `classify_provided` can't match them
//! against base, and they always Include — bloating the no-op
//! closure with linker-managed metadata that base already has.
//!
//! The fix: model the merged output as the closure-walk unit. One
//! phantom graph node per aggregator; its successors are the
//! contributing input sections; its trans_hash falls out of the
//! existing SCC roll-up. base records the phantom's identity →
//! merged-output address. classify_provided sees a real entry and
//! either matches (no-op case) or cascades (any contributor changed).
//!
//! Phantoms expose a graft-internal synthetic name
//! (`__graft_aggregate_<id>`) registered as a defined symbol on the
//! phantom, so the existing symhash machinery can route through them
//! without any new code path. Aggregators with real bracket symbols
//! (`.init_array` → `__init_array_start`/`end`) register those too.

/// One catalog entry per distinct linker-aggregated output.
pub struct Aggregator {
    /// Stable identifier used in the graft-internal synthetic symbol
    /// name (`__graft_aggregate_<id>`) and as the lookup key for the
    /// merged output's address in base.elf. For symbol-bracketed
    /// outputs this is also the output section name (`.init_array`,
    /// `.ctors`); for segment-consumed outputs it's a fabricated tag
    /// (`pt_note`, `pt_eh_frame`).
    pub id: &'static str,
    /// How to identify input sections that contribute to this output.
    pub contributor: Contributor,
    /// Real linker-script-defined symbols that bracket the merged
    /// output. Empty for outputs consumed via segment header.
    pub bracket_symbols: &'static [BracketSymbol],
    /// Where the merged output's start address lives in base.elf.
    /// Section-name lookup (`.init_array`, `.note.gnu.property`) for
    /// the typical case; bracket-symbol lookup for outputs whose
    /// section name doesn't match the contributor pattern minus the
    /// `.<priority>` suffix.
    pub base_addr_source: BaseAddrSource,
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

pub enum BaseAddrSource {
    /// Look up the merged output by section name in base.elf's
    /// section header table.
    SectionName(&'static str),
    /// Look up by a bracket symbol (whose value IS the start address)
    /// in base.elf's `.symtab`.
    SymbolName(&'static str),
}

/// The full catalog. Order does not matter; aggregators are mutually
/// exclusive on contributor matches by construction (each input
/// section matches at most one aggregator).
pub const AGGREGATORS: &[Aggregator] = &[
    // ---- Constructor / destructor arrays ----
    Aggregator {
        id: "init_array",
        contributor: Contributor::ExactOrDot(".init_array"),
        bracket_symbols: &[
            BracketSymbol { name: "__init_array_start", end: BracketEnd::Start },
            BracketSymbol { name: "__init_array_end",   end: BracketEnd::End },
        ],
        base_addr_source: BaseAddrSource::SectionName(".init_array"),
    },
    Aggregator {
        id: "fini_array",
        contributor: Contributor::ExactOrDot(".fini_array"),
        bracket_symbols: &[
            BracketSymbol { name: "__fini_array_start", end: BracketEnd::Start },
            BracketSymbol { name: "__fini_array_end",   end: BracketEnd::End },
        ],
        base_addr_source: BaseAddrSource::SectionName(".fini_array"),
    },
    Aggregator {
        id: "preinit_array",
        contributor: Contributor::ExactOrDot(".preinit_array"),
        bracket_symbols: &[
            BracketSymbol { name: "__preinit_array_start", end: BracketEnd::Start },
            BracketSymbol { name: "__preinit_array_end",   end: BracketEnd::End },
        ],
        base_addr_source: BaseAddrSource::SectionName(".preinit_array"),
    },
    Aggregator {
        id: "ctors",
        contributor: Contributor::ExactOrDot(".ctors"),
        bracket_symbols: &[],
        base_addr_source: BaseAddrSource::SectionName(".ctors"),
    },
    Aggregator {
        id: "dtors",
        contributor: Contributor::ExactOrDot(".dtors"),
        bracket_symbols: &[],
        base_addr_source: BaseAddrSource::SectionName(".dtors"),
    },
    // ---- Notes (consumed via PT_NOTE) ----
    Aggregator {
        id: "pt_note",
        contributor: Contributor::ExactOrDot(".note"),
        bracket_symbols: &[],
        base_addr_source: BaseAddrSource::SectionName(".note.gnu.property"),
    },
    // ---- Exception-handling tables (consumed via PT_GNU_EH_FRAME) ----
    Aggregator {
        id: "eh_frame",
        contributor: Contributor::ExactOrDot(".eh_frame"),
        bracket_symbols: &[],
        base_addr_source: BaseAddrSource::SectionName(".eh_frame"),
    },
];

/// Graft-internal synthetic symbol name for an aggregator. Used as a
/// always-present defined symbol on the phantom node so symhash
/// machinery routes through it even when no real bracket symbols exist
/// (PT_NOTE etc.).
pub fn synthetic_name(id: &str) -> String {
    format!("__graft_aggregate_{id}")
}

/// Returns the aggregator a given input section name contributes to,
/// if any. None means "ordinary input section, not an aggregator
/// contributor."
pub fn aggregator_for_section(name: &str) -> Option<&'static Aggregator> {
    AGGREGATORS.iter().find(|a| a.contributor.matches(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_array_contributor_match() {
        let a = aggregator_for_section(".init_array").unwrap();
        assert_eq!(a.id, "init_array");
        let a = aggregator_for_section(".init_array.65535").unwrap();
        assert_eq!(a.id, "init_array");
        // ".init" doesn't match the .init_array prefix idiom.
        assert!(aggregator_for_section(".init").is_none());
    }

    #[test]
    fn note_aggregator_catches_property_and_buildid() {
        let a = aggregator_for_section(".note.gnu.property").unwrap();
        assert_eq!(a.id, "pt_note");
        let a = aggregator_for_section(".note.gnu.build-id").unwrap();
        assert_eq!(a.id, "pt_note");
    }

    #[test]
    fn ordinary_text_section_is_not_a_contributor() {
        assert!(aggregator_for_section(".text").is_none());
        assert!(aggregator_for_section(".text._ZN3foo3bar17h0123456789abcdefE").is_none());
    }
}
