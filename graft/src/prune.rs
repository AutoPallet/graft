//! Per-`.o` pruning for overlay mode.
//!
//! Given a source object and the set of its sections the closure wants to
//! keep, rewrite it as a minimal ELF object retaining:
//!   - Only closure-member sections (drop everything else).
//!   - Symbols defined in kept sections (unchanged).
//!   - Relocations from kept sections. Targets satisfied by the kept
//!     sections themselves pass through (internal wiring — the only
//!     resolution prune does, because only prune sees the object's own
//!     symbol indexes). Every other target is dispatched through the
//!     `DisposeFn` callback (see `resolve.rs`), which answers with
//!     either a UND symbol (overlay re-emits the target / weak-undef
//!     mirror) or an anchor (`__graft_assumed_<vaddr>`, deduped by
//!     address; the reloc's own addend rides along so
//!     `S + A = vaddr + addend`). Anchors are emitted as *UND
//!     references*; the overlay run synthesizes one base-map object
//!     that defines every anchor — as a section symbol inside a map
//!     section placed at base's layout, or SHN_ABS for vaddrs outside
//!     base's image (ROM constants). Section-defined anchors work
//!     uniformly for PC-relative, absolute, GOT-relative AND
//!     TLS-flavored relocs, because to the linker they are ordinary
//!     defined symbols at known addresses.
//!
//! Prune deliberately contains NO name-resolution logic — that lives in
//! one place (`resolve::Resolver`), shared with the closure walk, so
//! inclusion and resolution cannot drift.
//!
//! See `docs/11-anon-provide.md` and `docs/14-identity-granularity.md`.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, anyhow, bail};
use object::{
    Architecture, BinaryFormat, Endianness, Object, ObjectSection, ObjectSymbol,
    RelocationFlags, RelocationTarget, SectionIndex, SectionKind, SymbolIndex, SymbolKind,
    SymbolScope,
    write::{
        self, Object as WObject, Relocation as WRelocation, Symbol as WSymbol,
        SymbolId, SymbolSection as WSymbolSection,
    },
};

use crate::resolve::{DisposeFn, RelocDisposition, RelocQuery};

/// Result of pruning one source `.o`.
#[derive(Debug)]
pub struct Pruned {
    pub bytes: Vec<u8>,
    pub kept_sections: usize,
    /// Count of relocations rewritten to a per-target anchor
    /// (`__graft_assumed_<hex>`). Reported in the overlay summary;
    /// useful for diagnosing whether a closure leans heavily on
    /// base-bound resolution vs internal kept-section refs.
    pub anchor_rewrites: usize,
    /// (name, assumed_address) for every reloc target this pruned
    /// `.o` resolved through base's symtab snapshot. Overlay collects
    /// these across all pruned objects and verifies post-link that
    /// overlay's symtab agrees on the address.
    pub assumed_names: Vec<(String, u64)>,
    /// Every anchor this object references: `(vaddr, tls)`, sorted +
    /// deduped. The overlay run unions these across pruned objects and
    /// synthesizes the base-map object that defines them.
    pub anchors: Vec<(u64, bool)>,
}

/// Prune `source_bytes` (a single `.o` file) against `keep`, the set of
/// 0-based indexes (matching `ParsedObject::sections`) that the closure
/// wants included. `dispose` answers every reloc the kept sections
/// don't satisfy internally.
pub fn prune_object(
    source_bytes: &[u8],
    keep: &HashSet<u32>,
    dispose: &DisposeFn<'_>,
) -> Result<Pruned> {
    let src = object::File::parse(source_bytes).context("parse source .o")?;

    let arch = match src.architecture() {
        object::Architecture::X86_64 => Architecture::X86_64,
        object::Architecture::Xtensa => Architecture::Xtensa,
        a => bail!("unsupported architecture {a:?}"),
    };
    let endian = if src.is_little_endian() {
        Endianness::Little
    } else {
        Endianness::Big
    };

    let mut out = WObject::new(BinaryFormat::Elf, arch, endian);

    // object::read section indexes are 1-based; our `keep` indexes are
    // 0-based (how ParsedObject numbers them).
    let is_kept = |idx: SectionIndex| keep.contains(&(idx.0 as u32).saturating_sub(1));

    // Pass 1: add kept sections.
    let mut sec_map: HashMap<SectionIndex, object::write::SectionId> = HashMap::new();
    for src_sec in src.sections() {
        let idx = src_sec.index();
        if !is_kept(idx) {
            continue;
        }
        let kind = src_sec.kind();
        let new_id = out.add_section(
            Vec::new(),
            src_sec.name().unwrap_or("").as_bytes().to_vec(),
            kind,
        );
        {
            let w_sec = out.section_mut(new_id);
            let align = src_sec.align().max(1);
            if kind.is_bss() {
                w_sec.append_bss(src_sec.size(), align);
            } else {
                let data = src_sec.data().unwrap_or(&[]).to_vec();
                w_sec.set_data(data, align);
            }
        }
        sec_map.insert(idx, new_id);
    }

    // Pass 2: symbols. Only defined-in-kept-section entries get ported
    // forward — every other target arrives via `dispose`. STT_FILE /
    // STT_SECTION are regenerated by the writer.
    let mut sym_map: HashMap<SymbolIndex, SymbolId> = HashMap::new();
    for src_sym in src.symbols() {
        let kind = src_sym.kind();
        if matches!(kind, SymbolKind::File | SymbolKind::Section) {
            continue;
        }
        let Some(idx) = src_sym.section_index() else {
            continue;
        };
        let Some(&new_sec_id) = sec_map.get(&idx) else {
            continue;
        };

        let scope = if matches!(src_sym.scope(), SymbolScope::Compilation | SymbolScope::Unknown) {
            write::SymbolScope::Compilation
        } else {
            write::SymbolScope::Dynamic
        };
        let wsym = WSymbol {
            name: src_sym.name().unwrap_or("").as_bytes().to_vec(),
            value: src_sym.address(),
            size: src_sym.size(),
            kind: map_kind(kind),
            scope,
            weak: src_sym.is_weak(),
            section: WSymbolSection::Section(new_sec_id),
            flags: write::SymbolFlags::None,
        };
        sym_map.insert(src_sym.index(), out.add_symbol(wsym));
    }

    // Per-address anchor references for base-bound relocs. Every reloc
    // that resolves to base address `vaddr` shares one UND symbol
    // (`__graft_assumed_<vaddr>`), deduped by address; the overlay
    // run's base-map object defines it at that address.
    //
    // Why one-symbol-per-target instead of a single `__graft_const
    // + (vaddr+A)`: GOTPCREL/GOTPCRELX populate the GOT slot with
    // the symbol VALUE (S), not S+A. With S=vaddr the slot correctly
    // holds the target's address; with S=0 the slot would hold 0
    // and the addend would miscombine into the instruction's disp.
    // PC32/ABS-style relocs are unaffected — they fold S+A directly.
    // See `docs/11-anon-provide.md` and docs/15.
    let mut addr_syms: HashMap<u64, (SymbolId, bool)> = HashMap::new();
    // UND symbols emitted on request, deduped by (name, weak).
    let mut und_syms: HashMap<(String, bool), SymbolId> = HashMap::new();
    // (name, vaddr) pairs for every verify-carrying anchor.
    let mut assumed_names: Vec<(String, u64)> = Vec::new();
    let mut anchor_rewrites: usize = 0;

    // Pass 3: relocations from kept sections. Internal wiring (targets
    // in this object's own kept sections) passes through; everything
    // else asks `dispose`.
    for src_sec in src.sections() {
        let Some(&new_sec_id) = sec_map.get(&src_sec.index()) else {
            continue;
        };
        let from_section = src_sec.name().unwrap_or("?").to_string();
        let section0 = (src_sec.index().0 as u32).saturating_sub(1);
        for (offset, r) in src_sec.relocations() {
            let r_type = match r.flags() {
                RelocationFlags::Elf { r_type } => r_type,
                _ => continue,
            };
            // R_*_NONE is reloc-type 0 across every supported arch
            // (x86_64, xtensa, arm, riscv) — it's a no-op placeholder.
            if r_type == 0 {
                continue;
            }

            let disposition = match r.target() {
                RelocationTarget::Symbol(sidx) => {
                    if let Some(&id) = sym_map.get(&sidx) {
                        Ok(id)
                    } else {
                        let src_sym = src
                            .symbol_by_index(sidx)
                            .map_err(|e| anyhow!("resolve reloc target: {e}"))?;
                        if matches!(src_sym.kind(), SymbolKind::Section) {
                            let target_sec = src_sym.section_index().ok_or_else(|| {
                                anyhow!("STT_SECTION symbol with no section in {from_section}")
                            })?;
                            if let Some(&new_id) = sec_map.get(&target_sec) {
                                Ok(out.section_symbol(new_id))
                            } else {
                                Err(dispose(&RelocQuery {
                                    section0,
                                    offset,
                                    r_type,
                                    addend: r.addend(),
                                    target_name: None,
                                    weak_ref: false,
                                    from_section: &from_section,
                                })?)
                            }
                        } else {
                            let name = src_sym.name().unwrap_or("");
                            if name.is_empty() {
                                bail!(
                                    "reloc in {from_section}: target symbol has no name \
                                     and no defining section"
                                );
                            }
                            Err(dispose(&RelocQuery {
                                section0,
                                offset,
                                r_type,
                                addend: r.addend(),
                                target_name: Some(name),
                                weak_ref: src_sym.is_weak(),
                                from_section: &from_section,
                            })?)
                        }
                    }
                }
                RelocationTarget::Section(target_sec) => {
                    if let Some(&new_id) = sec_map.get(&target_sec) {
                        Ok(out.section_symbol(new_id))
                    } else {
                        Err(dispose(&RelocQuery {
                            section0,
                            offset,
                            r_type,
                            addend: r.addend(),
                            target_name: None,
                            weak_ref: false,
                            from_section: &from_section,
                        })?)
                    }
                }
                RelocationTarget::Absolute => {
                    bail!("absolute reloc target not supported in {from_section}");
                }
                other => bail!("unsupported reloc target {other:?} in {from_section}"),
            };

            // A walk-translated anchor folds `value + addend` into its
            // vaddr; the emitted addend must be overridden (to 0), not
            // re-applied on top.
            let mut addend_override: Option<i64> = None;
            let sym_id = match disposition {
                Ok(internal) => internal,
                Err(RelocDisposition::Und { name, weak, tls }) => {
                    *und_syms.entry((name.clone(), weak)).or_insert_with(|| {
                        out.add_symbol(WSymbol {
                            name: name.into_bytes(),
                            value: 0,
                            size: 0,
                            // ld rejects a TLS definition bound from a
                            // non-TLS reference — mirror the type.
                            kind: if tls { SymbolKind::Tls } else { SymbolKind::Unknown },
                            scope: write::SymbolScope::Dynamic,
                            weak,
                            section: WSymbolSection::Undefined,
                            flags: write::SymbolFlags::None,
                        })
                    })
                }
                Err(RelocDisposition::Anchor { vaddr, tls, verify_name, addend }) => {
                    anchor_rewrites += 1;
                    addend_override = addend;
                    if let Some(name) = verify_name {
                        assumed_names.push((name, vaddr));
                    }
                    // Anchors dedup by target address: every reloc to the
                    // same vaddr shares one UND symbol (the reloc's own
                    // addend rides along, so S + A = vaddr + addend). The
                    // base-map object defines the name; STT_TLS on the
                    // reference so ld accepts TLS-flavored relocs against
                    // it (everything else is STT_NOTYPE).
                    let entry = addr_syms.entry(vaddr).or_insert_with(|| {
                        let id = out.add_symbol(WSymbol {
                            name: format!("__graft_assumed_{vaddr:016x}").into_bytes(),
                            value: 0,
                            size: 0,
                            kind: if tls { SymbolKind::Tls } else { SymbolKind::Unknown },
                            scope: write::SymbolScope::Linkage, // hidden: defined in-link
                            weak: false,
                            section: WSymbolSection::Undefined,
                            flags: write::SymbolFlags::None,
                        });
                        (id, tls)
                    });
                    if entry.1 != tls {
                        bail!(
                            "anchor {vaddr:#x} classified both TLS and non-TLS across \
                             relocs — resolver tls_range inconsistency"
                        );
                    }
                    entry.0
                }
            };

            out.add_relocation(
                new_sec_id,
                WRelocation {
                    offset,
                    symbol: sym_id,
                    addend: addend_override.unwrap_or_else(|| r.addend()),
                    flags: RelocationFlags::Elf { r_type },
                },
            )
            .with_context(|| format!("add reloc at {offset:#x} in {from_section}"))?;
        }
    }

    let bytes = out.write().map_err(|e| anyhow!("write pruned object: {e}"))?;
    // Dedup names — we may have rewritten many relocs to the same
    // target. Keep first (vaddr, name) pair; subsequent must agree
    // (they will, since a single overlay run uses a single resolution).
    assumed_names.sort();
    assumed_names.dedup();
    let mut anchors: Vec<(u64, bool)> = addr_syms
        .into_iter()
        .map(|(vaddr, (_, tls))| (vaddr, tls))
        .collect();
    anchors.sort_unstable();

    Ok(Pruned {
        bytes,
        kept_sections: sec_map.len(),
        anchor_rewrites,
        assumed_names,
        anchors,
    })
}

fn map_kind(k: SymbolKind) -> SymbolKind {
    // object::write rejects `Unknown` for defined symbols, but rustc emits
    // STT_NOTYPE for local labels like `.LC0` / `.LCPI0_0`. Map those to
    // `Label`, which also serializes to STT_NOTYPE.
    match k {
        SymbolKind::Unknown => SymbolKind::Label,
        other => other,
    }
}

/// Predicate helper: true if this section kind should be carried into
/// the pruned object (as opposed to things like metadata sections).
pub fn kept_section_kind(kind: SectionKind) -> bool {
    matches!(
        kind,
        SectionKind::Text
            | SectionKind::Data
            | SectionKind::ReadOnlyData
            | SectionKind::ReadOnlyString
            | SectionKind::UninitializedData
            | SectionKind::Tls
            | SectionKind::UninitializedTls
    )
}
