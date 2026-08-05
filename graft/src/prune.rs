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
//! See `docs/worklogs/11-anon-provide.md` and `docs/worklogs/14-identity-granularity.md`.

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

    // Pass 0: FDE-filter kept `.eh_frame` sections. BFD's eh_frame
    // parser hard-REQUIREs every FDE's pc target to be a section of the
    // SAME object (`rsec->owner == abfd` in elf-eh-frame.c) — an FDE
    // whose pc reloc became an `__graft_assumed_*` UND (unchanged text
    // anchored into base) or dangles (base gc'd the function) aborts
    // the parse for the whole section and ld silently drops it, taking
    // the *valid* FDEs down too. So prune keeps only FDEs whose pc
    // target section is kept in this object — the dropped ones cover
    // base-resident pcs that base's own unwind table already describes,
    // or code that exists nowhere. This is the "per-FDE splitting
    // inside prune" that roots.rs predicted. A filtered section with
    // zero surviving FDEs is dropped entirely.
    let mut eh_filters: HashMap<SectionIndex, EhFilter> = HashMap::new();
    for src_sec in src.sections() {
        let idx = src_sec.index();
        let name = src_sec.name().unwrap_or("");
        if !is_kept(idx) || !(name == ".eh_frame" || name.starts_with(".eh_frame.")) {
            continue;
        }
        // pc-keep decision per reloc offset: does the reloc's target
        // symbol live in a kept section of this object?
        let mut kept_by_offset: HashMap<u64, bool> = HashMap::new();
        for (off, r) in src_sec.relocations() {
            let target_sec = match r.target() {
                RelocationTarget::Symbol(sidx) => {
                    src.symbol_by_index(sidx).ok().and_then(|s| s.section_index())
                }
                RelocationTarget::Section(tsec) => Some(tsec),
                _ => None,
            };
            kept_by_offset.insert(off, target_sec.is_some_and(is_kept));
        }
        let data = src_sec.data().unwrap_or(&[]);
        let filter = filter_eh_frame(data, &|off| kept_by_offset.get(&off).copied().unwrap_or(false))
            .with_context(|| format!("FDE-filter {name}"))?;
        eh_filters.insert(idx, filter);
    }

    // Pass 1: add kept sections.
    let mut sec_map: HashMap<SectionIndex, object::write::SectionId> = HashMap::new();
    for src_sec in src.sections() {
        let idx = src_sec.index();
        if !is_kept(idx) {
            continue;
        }
        if let Some(f) = eh_filters.get(&idx)
            && f.kept_fdes == 0
        {
            continue; // every FDE dropped — no reason to carry the CIEs
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
            } else if let Some(f) = eh_filters.get(&idx) {
                w_sec.set_data(f.data.clone(), align);
            } else {
                let data = src_sec.data().unwrap_or(&[]).to_vec();
                w_sec.set_data(data, align);
            }
            // Mirror the source's sh_flags verbatim: object::write
            // otherwise INFERS flags from SectionKind, and sections
            // with nonstandard sh_type (`.eh_frame` = SHT_X86_64_UNWIND)
            // infer to sh_flags=0 — the pruned copy silently loses
            // SHF_ALLOC and ld drops it from the overlay image.
            // SHF_GROUP / SHF_LINK_ORDER are stripped: their referents
            // (group sections, sh_link targets) aren't ported.
            if let object::SectionFlags::Elf { sh_flags } = src_sec.flags() {
                const STRIP: u64 = (object::elf::SHF_GROUP | object::elf::SHF_LINK_ORDER) as u64;
                w_sec.flags = write::SectionFlags::Elf { sh_flags: sh_flags & !STRIP };
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
    // See `docs/worklogs/11-anon-provide.md` and docs/worklogs/15.
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
        let eh_filter = eh_filters.get(&src_sec.index());
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
            // FDE-filtered section: relocs of dropped records die with
            // them; survivors move to the compacted offset. `dispose`
            // queries still use the ORIGINAL offset — the scan's
            // recorded resolutions are keyed on it.
            let emit_offset = match eh_filter {
                Some(f) => match f.reloc_map.get(&offset) {
                    Some(&new_off) => new_off,
                    None => continue,
                },
                None => offset,
            };

            // Debug-referrer relocs never reach `dispose`: the scan
            // deliberately records no resolutions for non-alloc
            // sections (debug relocs dominate reloc volume by an order
            // of magnitude), and none are needed. A target kept in
            // this object wires internally (address attrs resolve to
            // true slack addresses at the overlay link; str/abbrev/line
            // offsets resolve through the concatenation-addressed
            // debug output sections). Any other target tombstones —
            // the reloc is dropped and the field's zero bytes read as
            // DWARF tombstone 0, exactly what ld emits for refs into
            // gc'd sections. Base's own DWARF still describes those
            // unchanged/absent functions.
            if from_section.starts_with(".debug_") {
                let internal: Option<SymbolId> = match r.target() {
                    RelocationTarget::Symbol(sidx) => {
                        if let Some(&id) = sym_map.get(&sidx) {
                            Some(id)
                        } else {
                            src.symbol_by_index(sidx).ok().and_then(|s| {
                                if !matches!(s.kind(), SymbolKind::Section) {
                                    return None;
                                }
                                s.section_index()
                                    .and_then(|t| sec_map.get(&t))
                                    .map(|&id| out.section_symbol(id))
                            })
                        }
                    }
                    RelocationTarget::Section(t) => {
                        sec_map.get(&t).map(|&id| out.section_symbol(id))
                    }
                    _ => None,
                };
                let Some(sym_id) = internal else { continue };
                out.add_relocation(
                    new_sec_id,
                    WRelocation {
                        offset,
                        symbol: sym_id,
                        addend: r.addend(),
                        flags: RelocationFlags::Elf { r_type },
                    },
                )
                .with_context(|| format!("add debug reloc at {offset:#x} in {from_section}"))?;
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
                    offset: emit_offset,
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

/// Result of FDE-filtering one `.eh_frame` section: compacted content
/// plus the reloc offset relocation map (old → new; absent = the
/// reloc's record was dropped).
#[derive(Debug)]
pub(crate) struct EhFilter {
    pub data: Vec<u8>,
    pub reloc_map: HashMap<u64, u64>,
    pub kept_fdes: usize,
}

/// Walk an input `.eh_frame`, keeping every CIE and exactly the FDEs
/// whose pc_begin reloc (the reloc at record offset +8) `keep_pc_at`
/// approves. Surviving FDEs get their CIE back-pointer re-derived
/// against the CIE's compacted position; relocs move with their
/// records. Anything structurally surprising (64-bit DWARF, truncated
/// records, an FDE whose CIE isn't in this section, an FDE with no pc
/// reloc) refuses — a wrong unwind table is worse than a refused
/// overlay.
pub(crate) fn filter_eh_frame(
    data: &[u8],
    keep_pc_at: &dyn Fn(u64) -> bool,
) -> Result<EhFilter> {
    let u32_at = |pos: usize| -> Result<u32> {
        data.get(pos..pos + 4)
            .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
            .ok_or_else(|| anyhow!(".eh_frame truncated at {pos:#x}"))
    };
    let mut out = Vec::with_capacity(data.len());
    let mut reloc_map: HashMap<u64, u64> = HashMap::new();
    // old CIE offset → new CIE offset.
    let mut cie_new: HashMap<usize, usize> = HashMap::new();
    let mut kept_fdes = 0usize;
    let mut pos = 0usize;
    while pos + 4 <= data.len() {
        let len = u32_at(pos)?;
        if len == 0 {
            break; // terminator; ld re-terminates output itself
        }
        if len == u32::MAX {
            bail!("64-bit DWARF length in .eh_frame at {pos:#x} — unsupported");
        }
        let end = pos + 4 + len as usize;
        if end > data.len() {
            bail!(".eh_frame record at {pos:#x} overruns section ({end:#x} > {:#x})", data.len());
        }
        let id = u32_at(pos + 4)?;
        if id == 0 {
            // CIE: always carried (offsets stay derivable for every
            // later FDE; ld's eh_frame editor drops unused CIEs).
            let new_pos = out.len();
            cie_new.insert(pos, new_pos);
            out.extend_from_slice(&data[pos..end]);
            for old_off in pos..end {
                reloc_map.insert(old_off as u64, (new_pos + (old_off - pos)) as u64);
            }
        } else {
            // FDE. `id` is the distance from its own field (pos+4) back
            // to the owning CIE.
            let cie_old = (pos + 4)
                .checked_sub(id as usize)
                .ok_or_else(|| anyhow!("FDE at {pos:#x}: CIE pointer {id:#x} underflows"))?;
            let Some(&cie_pos) = cie_new.get(&cie_old) else {
                bail!("FDE at {pos:#x}: CIE at {cie_old:#x} not found in this section");
            };
            if !keep_pc_at((pos + 8) as u64) {
                pos = end;
                continue;
            }
            let new_pos = out.len();
            out.extend_from_slice(&data[pos..end]);
            let new_id = u32::try_from(new_pos + 4 - cie_pos)?;
            out[new_pos + 4..new_pos + 8].copy_from_slice(&new_id.to_le_bytes());
            for old_off in pos..end {
                reloc_map.insert(old_off as u64, (new_pos + (old_off - pos)) as u64);
            }
            kept_fdes += 1;
        }
        pos = end;
    }
    Ok(EhFilter { data: out, reloc_map, kept_fdes })
}

#[cfg(test)]
mod eh_filter_tests {
    use super::*;

    /// Build one record: 4-byte length + id + payload.
    fn rec(id: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = ((payload.len() + 4) as u32).to_le_bytes().to_vec();
        v.extend_from_slice(&id.to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn drops_unkept_fdes_and_fixes_cie_pointers() {
        // Layout: CIE 0..0x14, FDE1 0x14..0x30 (kept), FDE2 0x30..0x4c
        // (dropped). FDE cie-pointers are field-position-relative:
        // FDE1's field at 0x18 -> id 0x18, FDE2's at 0x34 -> id 0x34.
        let cie = rec(0, &[0u8; 12]); // 20 bytes
        let fde1 = rec(0x18, &[1u8; 20]); // 28 bytes
        let fde2 = rec(0x34, &[2u8; 20]);
        let data: Vec<u8> = [cie.clone(), fde1.clone(), fde2].concat();
        let f = filter_eh_frame(&data, &|off| off == 0x14 + 8).unwrap();
        assert_eq!(f.kept_fdes, 1);
        // CIE + FDE1 only, FDE1 unmoved (nothing before it dropped).
        assert_eq!(f.data.len(), cie.len() + fde1.len());
        assert_eq!(f.reloc_map.get(&(0x14 + 8)), Some(&(0x14 + 8)));
        assert_eq!(f.reloc_map.get(&(0x30 + 8)), None);
    }

    #[test]
    fn compacts_and_rewrites_cie_pointer_after_a_drop() {
        // CIE 0..0x14, dropped FDE 0x14..0x30, kept FDE 0x30..0x4c —
        // the kept FDE moves up to 0x14 and its CIE back-pointer must
        // shrink from 0x34 to 0x18.
        let data: Vec<u8> =
            [rec(0, &[0u8; 12]), rec(0x18, &[1u8; 20]), rec(0x34, &[2u8; 20])].concat();
        let f = filter_eh_frame(&data, &|off| off == 0x30 + 8).unwrap();
        assert_eq!(f.kept_fdes, 1);
        assert_eq!(f.data.len(), 0x14 + 0x1c);
        // Moved FDE at 0x14; its cie field at 0x18 must now hold 0x18.
        assert_eq!(u32::from_le_bytes(f.data[0x18..0x1c].try_into().unwrap()), 0x18);
        // Its pc reloc moved back by 0x1c.
        assert_eq!(f.reloc_map.get(&(0x30 + 8)), Some(&(0x14 + 8)));
    }

    #[test]
    fn foreign_cie_reference_refuses() {
        let fde_only = rec(0x100, &[0u8; 20]);
        let err = filter_eh_frame(&fde_only, &|_| true).unwrap_err().to_string();
        assert!(err.contains("underflow") || err.contains("not found"), "{err}");
    }
}
