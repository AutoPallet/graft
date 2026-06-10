//! Per-`.o` pruning for overlay mode.
//!
//! Given a source object and the set of its sections the closure wants to
//! keep, rewrite it as a minimal ELF object retaining:
//!   - Only closure-member sections (drop everything else).
//!   - Symbols defined in kept sections (unchanged).
//!   - Relocations from kept sections, retargeted as follows:
//!     * Targets that resolve to a kept section/symbol pass through.
//!     * Targets that resolve to a base-defined address (a pruned-section
//!       symbol whose definition lives in base, or a UND symbol satisfied
//!       by base) get encoded as `(__graft_assumed_<vaddr>, addend =
//!       original_addend)`. The address is found *positionally*: the
//!       target's node `trans_hash` maps to base's section start address
//!       (`by_section`), plus the symbol's in-section offset. Anchors are
//!       SHN_ABS symbols (st_value = base_vaddr) deduped by address. The
//!       linker resolves references the same way it resolves any defined
//!       absolute symbol, so PC-relative, absolute, AND GOT-relative
//!       relocs all work uniformly. No PROVIDE() or symbol-name plumbing.
//!
//! See `docs/11-anon-provide.md` and `docs/14-identity-granularity.md`.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, anyhow, bail};
use object::{
    Architecture, BinaryFormat, Endianness, Object, ObjectSection, ObjectSymbol,
    RelocationFlags, RelocationTarget, SectionIndex, SectionKind, SymbolIndex, SymbolKind,
    SymbolScope,
    write::{
        self, Object as WObject, Relocation as WRelocation, SectionId, Symbol as WSymbol,
        SymbolId, SymbolSection as WSymbolSection,
    },
};

/// Resolves overlay-side references against base, **positionally**: a
/// reference's target maps to a node `trans_hash` + an in-section offset,
/// and `by_section[trans_hash] + offset` is the base address. See
/// `docs/14-identity-granularity.md`.
pub struct BaseResolver<'a> {
    /// Base's content-keyed section table: `trans_hash → section base
    /// address`. The primary lookup — a content-matched reference anchors
    /// at `by_section[th] + offset`.
    pub by_section: &'a HashMap<crate::hash::TransHash, u64>,
    /// `trans_hash`es base placed at more than one distinct address
    /// (content-identical sections it did not fold). A *named* reference
    /// to one resolves to base's exact copy via `base_symtab` (preserving
    /// address identity); an `STT_SECTION` reference bails.
    pub ambiguous_sections: &'a HashSet<crate::hash::TransHash>,
    /// Overlay-side `name → (defining node trans_hash, in-section
    /// offset)` for globals, `(name, tu_id) → …` for locals. Translates a
    /// raw reloc target name into the positional base lookup.
    pub overlay_globals: &'a HashMap<String, (crate::hash::TransHash, u64)>,
    pub overlay_locals: &'a HashMap<(String, [u8; 8]), (crate::hash::TransHash, u64)>,
    /// Fallback when a reloc to an STB_LOCAL target's source-`.o` `tu_id`
    /// doesn't match the defining `.o` (rust internal-linkage symbols
    /// accessed cross-CGU). First-write-wins per name; safe because
    /// identical content → identical trans_hash → an interchangeable copy.
    pub overlay_locals_any_tu: &'a HashMap<String, (crate::hash::TransHash, u64)>,
    /// `--wrap=<sym>` targets (extracted from the link argv). Wrapped
    /// names get their reloc redirected to `__wrap_<sym>` at prune time
    /// and resolved through the same positional path as any other
    /// base-defined function.
    pub wrapped: &'a HashSet<String>,
    /// Snapshot of base's post-link `.symtab` keyed by name. The
    /// channel-of-last-resort: when a name isn't in overlay's scan (crt /
    /// startup, linker-script absolutes, ROM/PROVIDE, aggregator
    /// brackets, prebuilt-lib symbols) — and the disambiguator for a
    /// named reference into an `ambiguous_sections` hash — prune assumes
    /// base linked it here, anchors a SHN_ABS at this address, and records
    /// the assumption for post-link verify. Names base defined at
    /// multiple distinct addresses are excluded (see
    /// `base_symtab_ambiguous`).
    pub base_symtab: &'a HashMap<String, u64>,
    /// Names base defined at more than one distinct address (same-named
    /// locals across TUs). Channel 3 has no tu_id to disambiguate, so
    /// rather than silently bind to an arbitrary one it errors.
    pub base_symtab_ambiguous: &'a HashSet<String>,
    /// `trans_hash`es of every closure-included node. Cross-`.o` relocs
    /// to these stay UND so ld resolves them to overlay's re-emitted copy
    /// (their content differs from base — closure inclusion gates on that).
    pub closure_trans_hashes: &'a HashSet<crate::hash::TransHash>,
    /// `trans_hash`es of nodes backed by non-content-addressable
    /// sections (mutable data / NOBITS / zero-size). When one of these
    /// is *ambiguous* (base placed identical name+content at several
    /// addresses) and a reference can't be pinned by name, resolution
    /// BAILS instead of using the representative copy — byte-identical
    /// mutable sections are distinct variables, and a representative
    /// bind would silently alias program state. Read-only/exec content
    /// keeps the representative shortcut (any copy reads the same).
    pub mutable_trans_hashes: &'a HashSet<crate::hash::TransHash>,
}

impl<'a> BaseResolver<'a> {
    /// Translate a reference `name` (with optional `tu_id` for locals)
    /// into its `(trans_hash, in-section offset)` via the overlay scan.
    fn offset_of(&self, name: &str, was_local: bool, tu_id: [u8; 8]) -> Option<(crate::hash::TransHash, u64)> {
        if was_local {
            self.overlay_locals
                .get(&(name.to_string(), tu_id))
                .copied()
                .or_else(|| self.overlay_globals.get(name).copied())
                .or_else(|| self.overlay_locals_any_tu.get(name).copied())
        } else {
            self.overlay_globals
                .get(name)
                .copied()
                .or_else(|| self.overlay_locals_any_tu.get(name).copied())
        }
    }
}

/// Result of pruning one source `.o`.
#[derive(Debug)]
pub struct Pruned {
    pub bytes: Vec<u8>,
    pub kept_sections: usize,
    /// Count of relocations rewritten to a per-target SHN_ABS anchor
    /// (`__graft_assumed_<hex>`). Reported in the overlay summary;
    /// useful for diagnosing whether a closure leans heavily on
    /// base-bound resolution vs internal kept-section refs.
    pub abs_rewrites: usize,
    /// (name, assumed_address) for every reloc target this pruned
    /// `.o` resolved through `base_symtab` (the channel-of-last-resort).
    /// Overlay collects these across all pruned objects and verifies
    /// post-link that overlay's symtab agrees on the address.
    pub assumed_names: Vec<(String, u64)>,
}

/// Prune `source_bytes` (a single `.o` file) against `keep`, the set of
/// 0-based indexes (matching `ParsedObject::sections`) that the closure
/// wants included. `base` resolves any reloc target whose definition was
/// pruned (or was already UND) to the corresponding address in base.elf.
pub fn prune_object(
    source_bytes: &[u8],
    source_tu_id: [u8; 8],
    keep: &HashSet<u32>,
    base: &BaseResolver<'_>,
    // `0-based section index → node trans_hash` for this object, so
    // `STT_SECTION` relocs into pruned sections resolve positionally.
    section_trans_hash: &HashMap<u32, crate::hash::TransHash>,
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
    let mut sec_map: HashMap<SectionIndex, SectionId> = HashMap::new();
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
    // forward — every other reference becomes a SHN_ABS-encoded reloc
    // computed against `base`. STT_FILE / STT_SECTION are regenerated
    // by the writer.
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

    // Per-address SHN_ABS anchors for base-bound relocs. Every reloc that
    // resolves to base address `vaddr` shares one symbol
    // (`__graft_assumed_<vaddr>`, st_value = vaddr), deduped by address.
    //
    // Why one-symbol-per-target instead of a single `__graft_const
    // + (vaddr+A)`: GOTPCREL/GOTPCRELX populate the GOT slot with
    // the symbol VALUE (S), not S+A. With S=vaddr the slot correctly
    // holds the target's address; with S=0 the slot would hold 0
    // and the addend would miscombine into the instruction's disp.
    // PC32/ABS-style relocs are unaffected — they fold S+A directly.
    // See `docs/11-anon-provide.md`.
    let mut addr_syms: HashMap<[u8; 16], SymbolId> = HashMap::new();
    // (name, vaddr) pairs for every named-symbol Anchor. Overlay
    // collects these across all pruned objects and post-link checks
    // the linker placed each name at vaddr.
    let mut assumed_names: Vec<(String, u64)> = Vec::new();
    // Cache: target_sec_idx -> base vaddr of the section's start.
    let mut section_base_vaddr: HashMap<SectionIndex, i64> = HashMap::new();
    // Cache: wrap-targeted symbol name -> UND SymbolId in output.
    // Lazily emitted so we don't add UND entries for wrap names
    // that don't appear in any reloc.
    let mut wrap_sym_map: HashMap<String, SymbolId> = HashMap::new();
    let mut abs_rewrites: usize = 0;

    // Pass 3: relocations from kept sections.
    for src_sec in src.sections() {
        let Some(&new_sec_id) = sec_map.get(&src_sec.index()) else {
            continue;
        };
        let from_section = src_sec.name().unwrap_or("?").to_string();
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

            let addend = r.addend();

            let outcome = match r.target() {
                RelocationTarget::Symbol(sidx) => {
                    if let Some(&id) = sym_map.get(&sidx) {
                        Outcome::Internal { sym_id: id, addend_extra: 0 }
                    } else {
                        let src_sym = src
                            .symbol_by_index(sidx)
                            .map_err(|e| anyhow!("resolve reloc target: {e}"))?;
                        if matches!(src_sym.kind(), SymbolKind::Section) {
                            let target_sec_idx = src_sym.section_index().ok_or_else(|| {
                                anyhow!("STT_SECTION symbol with no section in {from_section}")
                            })?;
                            section_target_outcome(
                                target_sec_idx,
                                &sec_map,
                                &mut section_base_vaddr,
                                base,
                                section_trans_hash,
                                &mut out,
                                &from_section,
                            )?
                        } else {
                            let name = src_sym.name().unwrap_or("");
                            if name.is_empty() {
                                bail!(
                                    "reloc in {from_section}: target symbol has no name and no defining section"
                                );
                            }
                            let was_local = matches!(
                                src_sym.scope(),
                                SymbolScope::Compilation | SymbolScope::Unknown
                            );
                            // Wraps: ld would redirect `<name>` →
                            // `__wrap_<name>`. Pre-apply the rename and
                            // let normal positional routing find it.
                            let lookup_name: String = if base.wrapped.contains(name) {
                                format!("__wrap_{name}")
                            } else {
                                name.to_string()
                            };
                            // Positional routing (see docs/14):
                            //   1. overlay re-emits the target's section
                            //      (its trans_hash is in the closure) →
                            //      UND so ld binds to overlay's copy.
                            //   2. base has the section content
                            //      (trans_hash in by_section) → SHN_ABS
                            //      anchor at base section start + offset.
                            //   3. content-identical multi-address section
                            //      → resolve the named symbol to base's
                            //      exact copy via base_symtab + verify.
                            //   3b. overlay never saw the name but base
                            //      resolved it (crt/script/bracket/ROM/
                            //      prebuilt) → base_symtab anchor + verify.
                            //   4. otherwise bail — never bind to a stale
                            //      or guessed address.
                            let off_entry = base.offset_of(&lookup_name, was_local, source_tu_id);
                            if let Some((th, _off)) = off_entry
                                && base.closure_trans_hashes.contains(&th)
                            {
                                // (1) target re-emitted by overlay; UND.
                                let wsym_id = match wrap_sym_map.get(lookup_name.as_str()) {
                                    Some(&id) => id,
                                    None => {
                                        let id = out.add_symbol(WSymbol {
                                            name: lookup_name.as_bytes().to_vec(),
                                            value: 0,
                                            size: 0,
                                            kind: SymbolKind::Unknown,
                                            scope: write::SymbolScope::Dynamic,
                                            weak: false,
                                            section: WSymbolSection::Undefined,
                                            flags: write::SymbolFlags::None,
                                        });
                                        wrap_sym_map.insert(lookup_name.clone(), id);
                                        id
                                    }
                                };
                                Outcome::Internal { sym_id: wsym_id, addend_extra: 0 }
                            } else if let Some((th, off)) = off_entry
                                && let Some(&sec_addr) = base.by_section.get(&th)
                            {
                                if base.ambiguous_sections.contains(&th) {
                                    if let Some(&addr) = base.base_symtab.get(&lookup_name) {
                                        // (2a) base holds this content at several
                                        // distinct addresses, but the *name* is
                                        // unique in base.symtab → these are
                                        // genuinely distinct byte-identical
                                        // symbols; pin base's exact copy to
                                        // preserve address identity, verify.
                                        Outcome::Anchor {
                                            vaddr: addr as i64,
                                            verify_name: Some(lookup_name.clone()),
                                        }
                                    } else if base.mutable_trans_hashes.contains(&th) {
                                        // Ambiguous *mutable* content that the
                                        // name can't pin: the copies are
                                        // distinct variables, not interchangeable
                                        // bytes. A representative bind would
                                        // silently alias program state.
                                        bail!(
                                            "reloc in {from_section}: {lookup_name} \
                                             (local={was_local}) resolves to mutable \
                                             section content base placed at multiple \
                                             addresses, and the name can't pin one copy \
                                             — refusing to alias distinct variables."
                                        );
                                    } else {
                                        // Same-name read-only duplicate
                                        // (interchangeable): the representative
                                        // copy is byte-identical, any copy reads
                                        // the same.
                                        Outcome::Anchor {
                                            vaddr: sec_addr as i64 + off as i64,
                                            verify_name: None,
                                        }
                                    }
                                } else {
                                    // (2) clean positional content match →
                                    // base section start + offset is sound.
                                    Outcome::Anchor {
                                        vaddr: sec_addr as i64 + off as i64,
                                        verify_name: None,
                                    }
                                }
                            } else if off_entry.is_some() {
                                // Overlay scanned a definition whose content
                                // is NOT in base (trans_hash absent from
                                // by_section) and the closure didn't re-emit
                                // it. Binding to a base address would call
                                // stale code — bail.
                                bail!(
                                    "reloc in {from_section}: {lookup_name} (local={was_local}) \
                                     has overlay content that differs from base but is not in the \
                                     closure — refusing to bind to a stale address. Likely a \
                                     closure / scan-discovery bug."
                                );
                            } else if let Some(&addr) = base.base_symtab.get(&lookup_name) {
                                // (3b) overlay never saw it; base resolved
                                // it (script absolute, PROVIDE, ROM, crt,
                                // aggregator bracket, prebuilt-lib symbol).
                                if std::env::var("GRAFT_DEBUG_CH3").is_ok() {
                                    eprintln!(
                                        "graft DEBUG ch3: {from_section} -> {lookup_name} @ {addr:#x}",
                                    );
                                }
                                Outcome::Anchor {
                                    vaddr: addr as i64,
                                    verify_name: Some(lookup_name.clone()),
                                }
                            } else if base.base_symtab_ambiguous.contains(&lookup_name) {
                                bail!(
                                    "reloc in {from_section}: {lookup_name} (local={was_local}) \
                                     is defined at multiple distinct addresses in base.elf — \
                                     can't disambiguate without a tu_id (upstream scan gap)."
                                );
                            } else if src_sym.is_weak() {
                                // Weak undef: base resolved it to 0 (absent
                                // from base.symtab); mirror with a weak UND.
                                let wsym_id = match wrap_sym_map.get(lookup_name.as_str()) {
                                    Some(&id) => id,
                                    None => {
                                        let id = out.add_symbol(WSymbol {
                                            name: lookup_name.as_bytes().to_vec(),
                                            value: 0,
                                            size: 0,
                                            kind: SymbolKind::Unknown,
                                            scope: write::SymbolScope::Dynamic,
                                            weak: true,
                                            section: WSymbolSection::Undefined,
                                            flags: write::SymbolFlags::None,
                                        });
                                        wrap_sym_map.insert(lookup_name.clone(), id);
                                        id
                                    }
                                };
                                Outcome::Internal { sym_id: wsym_id, addend_extra: 0 }
                            } else {
                                bail!(
                                    "reloc in {from_section}: can't resolve {lookup_name} \
                                     (local={was_local}) — not in overlay scan, not in base's \
                                     section table, not in base.symtab snapshot. Likely an \
                                     upstream scan-discovery bug."
                                );
                            }
                        }
                    }
                }
                RelocationTarget::Section(target_sec_idx) => section_target_outcome(
                    target_sec_idx,
                    &sec_map,
                    &mut section_base_vaddr,
                    base,
                    section_trans_hash,
                    &mut out,
                    &from_section,
                )?,
                RelocationTarget::Absolute => {
                    bail!("absolute reloc target not supported in {from_section}");
                }
                other => bail!("unsupported reloc target {other:?} in {from_section}"),
            };

            let (sym_id, final_addend) = match outcome {
                Outcome::Internal { sym_id, addend_extra } => (sym_id, addend + addend_extra),
                Outcome::Anchor { vaddr, verify_name } => {
                    abs_rewrites += 1;
                    if let Some(name) = verify_name {
                        assumed_names.push((name, vaddr as u64));
                    }
                    // Anchors dedup by target address: every reloc to the
                    // same vaddr shares one SHN_ABS symbol (the reloc's own
                    // addend rides along, so S + A = vaddr + addend).
                    let mut key = [0u8; 16];
                    key[..8].copy_from_slice(&(vaddr as u64).to_le_bytes());
                    let csym = *addr_syms.entry(key).or_insert_with(|| {
                        out.add_symbol(WSymbol {
                            name: format!("__graft_assumed_{:016x}", vaddr as u64).into_bytes(),
                            value: vaddr as u64,
                            size: 0,
                            kind: SymbolKind::Label, // STT_NOTYPE
                            scope: write::SymbolScope::Compilation, // STB_LOCAL
                            weak: false,
                            section: WSymbolSection::Absolute,
                            flags: write::SymbolFlags::None,
                        })
                    });
                    (csym, addend)
                }
            };

            out.add_relocation(
                new_sec_id,
                WRelocation {
                    offset,
                    symbol: sym_id,
                    addend: final_addend,
                    flags: RelocationFlags::Elf { r_type },
                },
            )
            .with_context(|| format!("add reloc at {offset:#x} in {from_section}"))?;
        }
    }

    // Helper local fn declared up here so the borrow-checker sees one
    // mutable borrow of `out` at a time inside the loop. An STT_SECTION
    // reloc into a *pruned* section resolves positionally: the section's
    // node trans_hash → base section start (the reloc's addend already
    // carries the in-section offset).
    fn section_target_outcome(
        target_sec_idx: SectionIndex,
        sec_map: &HashMap<SectionIndex, SectionId>,
        section_base_vaddr: &mut HashMap<SectionIndex, i64>,
        base: &BaseResolver<'_>,
        section_trans_hash: &HashMap<u32, crate::hash::TransHash>,
        out: &mut WObject<'_>,
        from_section: &str,
    ) -> Result<Outcome> {
        if let Some(&new_id) = sec_map.get(&target_sec_idx) {
            let sym_id = out.section_symbol(new_id);
            return Ok(Outcome::Internal { sym_id, addend_extra: 0 });
        }
        let vaddr = if let Some(&v) = section_base_vaddr.get(&target_sec_idx) {
            v
        } else {
            // `keep`/scan index sections 0-based; object::read is 1-based.
            let sec0 = (target_sec_idx.0 as u32).checked_sub(1).ok_or_else(|| {
                anyhow!("section index 0 (ehdr) as reloc target in {from_section}")
            })?;
            let th = section_trans_hash.get(&sec0).ok_or_else(|| {
                anyhow!(
                    "reloc from {from_section} into pruned section #{}: no scan node — \
                     graft can't pin its base address",
                    target_sec_idx.0
                )
            })?;
            // An STT_SECTION ref carries no name to disambiguate with, so
            // an ambiguous (content-identical multi-address) section
            // resolves to base's representative copy — sound for
            // read-only/exec content (its bytes are identical, which is
            // what a section+addend reference reads), NEVER for mutable
            // content (byte-identical mutable sections are distinct
            // variables; a representative bind silently aliases state).
            if base.ambiguous_sections.contains(th)
                && base.mutable_trans_hashes.contains(th)
            {
                bail!(
                    "reloc from {from_section} into pruned section #{}: mutable section \
                     content base placed at multiple addresses, and a section ref has \
                     no name to pin one copy — refusing to alias distinct variables.",
                    target_sec_idx.0
                );
            }
            let v = if let Some(&addr) = base.by_section.get(th) {
                addr as i64
            } else {
                bail!(
                    "reloc from {from_section} into pruned section #{}: section content \
                     not found in base (closure / scan-discovery gap)",
                    target_sec_idx.0
                );
            };
            section_base_vaddr.insert(target_sec_idx, v);
            v
        };
        Ok(Outcome::Anchor { vaddr, verify_name: None })
    }

    let bytes = out.write().map_err(|e| anyhow!("write pruned object: {e}"))?;
    // Dedup names — we may have rewritten many relocs to the same
    // target. Keep first (vaddr, name) pair; subsequent must agree
    // (they will, since a single prune run uses a single resolution).
    assumed_names.sort();
    assumed_names.dedup();

    Ok(Pruned {
        bytes,
        kept_sections: sec_map.len(),
        abs_rewrites,
        assumed_names,
    })
}

enum Outcome {
    Internal { sym_id: SymbolId, addend_extra: i64 },
    /// Resolved against base: the reloc is rewritten to a SHN_ABS anchor
    /// (`__graft_assumed_<vaddr>`, st_value = vaddr); the original addend
    /// rides along so `S + A = vaddr + addend`. Anchors dedup by vaddr.
    /// `verify_name = Some(name)` for resolutions that assume base.elf's
    /// symtab address (channel 3 / ambiguous-section disambiguation) —
    /// overlay post-link checks `name` landed at `vaddr`. `None` for
    /// positional (content-keyed) anchors.
    Anchor {
        vaddr: i64,
        verify_name: Option<String>,
    },
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
