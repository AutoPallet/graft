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
//!       by base) get encoded as `(__graft_sym_<symhash>, addend =
//!       original_addend)`. Each unique target gets its own SHN_ABS
//!       symbol (st_value = base_vaddr), keyed on content (the target's
//!       symhash) so the emitted name is stable across base rebuilds.
//!       The linker resolves references the same way it resolves any
//!       defined absolute symbol, so PC-relative, absolute, AND
//!       GOT-relative relocs all work uniformly. No PROVIDE() or
//!       symbol-name plumbing required.
//!
//! See `docs/11-anon-provide.md` for the rationale.

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

/// Resolves overlay-side symbol references against base.
///
/// `globals` covers all defined symbols in base.elf's `.symtab` keyed by
/// name (catches static-lib symbols too). `locals` covers STB_LOCAL
/// entries keyed by `(name, tu_id)`, sourced from base's `.graft.symhash`.
pub struct BaseResolver<'a> {
    /// Content-keyed: `symhash → SymHashEntry`. The primary lookup
    /// table — pull this section's address from base whenever overlay's
    /// symhash for it matches.
    pub by_symhash: &'a HashMap<crate::hash::Symhash, crate::metadata::SymHashEntry>,
    /// Per-symbol overlay-side fingerprints: `name → symhash` for
    /// globals, `(name, tu_id) → symhash` for locals. Used to
    /// translate raw reloc target names (which is all prune sees in
    /// each `.o`'s symtab) into the content-keyed lookup against
    /// `by_symhash`.
    pub overlay_symhash_globals: &'a HashMap<String, crate::hash::Symhash>,
    pub overlay_symhash_locals: &'a HashMap<(String, [u8; 8]), crate::hash::Symhash>,
    /// Fallback when a reloc to a STB_LOCAL target's source-`.o`
    /// `tu_id` doesn't match the target's defining `.o` (e.g. rust
    /// internal-linkage symbols accessed cross-CGU). First-write-wins
    /// per name across all TUs; safe because identical content
    /// produces the same symhash regardless of where it's defined.
    pub overlay_symhash_locals_any_tu: &'a HashMap<String, crate::hash::Symhash>,
    /// `--wrap=<sym>` targets (extracted from the link argv).
    /// Wrapped names get their reloc redirected to `__wrap_<sym>` at
    /// prune time and resolved through the same symhash path as any
    /// other base-defined function.
    pub wrapped: &'a HashSet<String>,
    /// Snapshot of base's post-link `.symtab` keyed by name. The
    /// channel-of-last-resort: when a name isn't matched by overlay's
    /// scan or by `by_symhash`, prune assumes base linked it to this
    /// address, rewrites the reloc to a per-name SHN_ABS anchor, and
    /// records the assumption for post-link verify. Subsumes the
    /// previous "linker-script absolute" handling — those names are
    /// in this map automatically.
    pub base_symtab: &'a HashMap<String, u64>,
    /// Symhashes of every symbol defined in a closure-included
    /// section. Cross-`.o` relocs to these must stay as UND symbol
    /// references so ld resolves them to overlay's re-emitted copy.
    /// (Categorically equivalent to "trans_hash differs from base"
    /// since closure inclusion already gates on that.)
    pub closure_symhashes: &'a HashSet<crate::hash::Symhash>,
}

impl<'a> BaseResolver<'a> {
    /// Look up `name` (with optional `tu_id` for locals) in overlay's
    /// per-symbol symhash table, then in base's `by_symhash`. Returns
    /// `(symhash, address)` on hit so callers can decide whether the
    /// symbol's defining section is also in the closure.
    fn resolve(
        &self,
        name: &str,
        was_local: bool,
        tu_id: [u8; 8],
    ) -> Option<(crate::hash::Symhash, u64)> {
        let sh = if was_local {
            self.overlay_symhash_locals
                .get(&(name.to_string(), tu_id))
                .copied()
                .or_else(|| self.overlay_symhash_globals.get(name).copied())
                .or_else(|| self.overlay_symhash_locals_any_tu.get(name).copied())?
        } else {
            self.overlay_symhash_globals
                .get(name)
                .copied()
                .or_else(|| self.overlay_symhash_locals_any_tu.get(name).copied())?
        };
        let entry = self.by_symhash.get(&sh)?;
        Some((sh, entry.address))
    }
}

/// Result of pruning one source `.o`.
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

    // Per-target SHN_ABS anchors for base-bound relocs. Each unique
    // resolution target gets its own symbol
    // (`__graft_assumed_<hex>`, st_value = vaddr), keyed by a
    // content-stable identifier (symhash for content-matched
    // resolutions, blake3(name) for name-only resolutions, surrogate
    // symhash for section anchors). Stable across rebuilds whose
    // address layout shifts but whose symbol contents don't.
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
    // Cache: target_sec_idx -> (base vaddr of section start, surrogate
    // symhash). Surrogate vaddr is anchor's base vaddr minus its
    // offset within the section; symhash is kept around for dedup
    // keying when emitting the SHN_ABS anchor.
    let mut section_base_vaddr: HashMap<SectionIndex, (i64, crate::hash::Symhash)> = HashMap::new();
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
                                &src,
                                &sec_map,
                                &mut section_base_vaddr,
                                base,
                                source_tu_id,
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
                            // `__wrap_<name>`. Pre-apply the rename
                            // and let normal symhash routing find it.
                            // `__wrap_<name>` is a regular function in
                            // base, so it has a symhash entry like
                            // anything else.
                            let lookup_name: String = if base.wrapped.contains(name) {
                                format!("__wrap_{name}")
                            } else {
                                name.to_string()
                            };
                            // Symhash routing:
                            //   1. Overlay sees this symbol AND its
                            //      symhash is in the closure → UND so
                            //      ld resolves to overlay's re-emitted
                            //      copy.
                            //   2. Overlay sees it AND base has a
                            //      matching symhash → SHN_ABS-bridge to
                            //      base's address.
                            //   3. Overlay doesn't see it BUT the name
                            //      is `SHN_ABS` in base (linker-script
                            //      absolute) → emit UND and let
                            //      overlay's same script resolve it.
                            //   4. Otherwise: hard error. We don't
                            //      silently fall back to name+address
                            //      lookup — that path would mask real
                            //      bugs (lazy-archive misses, content
                            //      drift, etc.).
                            let overlay_sh = if was_local {
                                base.overlay_symhash_locals
                                    .get(&(lookup_name.clone(), source_tu_id))
                                    .copied()
                                    .or_else(|| base.overlay_symhash_globals.get(&lookup_name).copied())
                                    .or_else(|| base.overlay_symhash_locals_any_tu.get(&lookup_name).copied())
                            } else {
                                base.overlay_symhash_globals
                                    .get(&lookup_name)
                                    .copied()
                                    .or_else(|| base.overlay_symhash_locals_any_tu.get(&lookup_name).copied())
                            };
                            if let Some(sh) = overlay_sh
                                && base.closure_symhashes.contains(&sh)
                            {
                                // (1) Symbol is in overlay's closure
                                // (re-emitted). UND in this `.o`; ld
                                // resolves to the overlay-side def.
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
                            } else if let Some(sh) = overlay_sh
                                && let Some(entry) = base.by_symhash.get(&sh)
                            {
                                // (2) Content-keyed match against base.
                                // The symbol's symhash is identical to
                                // base's, so base's address is the right
                                // bridge target. Anchor key is the
                                // symhash (stable across rebuilds).
                                Outcome::Anchor {
                                    vaddr: entry.address as i64,
                                    key: sh,
                                    verify_name: Some(lookup_name.clone()),
                                }
                            } else if let Some(&addr) = base.base_symtab.get(&lookup_name) {
                                // (3) Channel-of-last-resort: name was
                                // resolved by base's linker but graft's
                                // scan didn't see a content-keyed entry
                                // (linker-script absolute, PROVIDE
                                // default, weak fallback, etc.). Assume
                                // base's address; anchor keyed by name
                                // hash; verify post-link.
                                let mut k = [0u8; 16];
                                k.copy_from_slice(
                                    &blake3::hash(lookup_name.as_bytes()).as_bytes()[..16],
                                );
                                Outcome::Anchor {
                                    vaddr: addr as i64,
                                    key: k,
                                    verify_name: Some(lookup_name.clone()),
                                }
                            } else if src_sym.is_weak() {
                                // Weak undef: base's linker also
                                // couldn't find a definition and
                                // resolved this to address 0 (no
                                // symtab entry — that's why
                                // base_symtab missed). Emit UND in
                                // overlay's link too; overlay's
                                // linker will apply identical
                                // weak-undef → 0 semantics.
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
                            } else if overlay_sh.is_some() {
                                bail!(
                                    "reloc in {from_section}: {lookup_name} (local={was_local}) \
                                     has overlay symhash but no matching base entry — \
                                     content drift but not in closure (graft bug?)"
                                );
                            } else {
                                bail!(
                                    "reloc in {from_section}: can't resolve {lookup_name} \
                                     (local={was_local}) — not in overlay scan, not in base \
                                     symhash table, not in base.symtab snapshot. Likely an \
                                     upstream scan-discovery bug."
                                );
                            }
                        }
                    }
                }
                RelocationTarget::Section(target_sec_idx) => section_target_outcome(
                    target_sec_idx,
                    &src,
                    &sec_map,
                    &mut section_base_vaddr,
                    base,
                    source_tu_id,
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
                Outcome::Anchor { vaddr, key, verify_name } => {
                    abs_rewrites += 1;
                    if let Some(name) = verify_name {
                        assumed_names.push((name, vaddr as u64));
                    }
                    let csym = *addr_syms.entry(key).or_insert_with(|| {
                        // Use first 8 bytes of the dedup key as the
                        // anchor's hex tag. Collisions across
                        // distinct keys would produce duplicate
                        // anchor names; same-key inserts are deduped
                        // by the HashMap entry.
                        let hex: String = key[..8].iter().map(|b| format!("{b:02x}")).collect();
                        out.add_symbol(WSymbol {
                            name: format!("__graft_assumed_{hex}").into_bytes(),
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

    // Helper closure-like local fn declared up here so the borrow-checker
    // sees one mutable borrow of `out` at a time inside the loop.
    fn section_target_outcome<'src>(
        target_sec_idx: SectionIndex,
        src: &object::File<'src>,
        sec_map: &HashMap<SectionIndex, SectionId>,
        section_base_vaddr: &mut HashMap<SectionIndex, (i64, crate::hash::Symhash)>,
        base: &BaseResolver<'_>,
        tu_id: [u8; 8],
        out: &mut WObject<'_>,
        from_section: &str,
    ) -> Result<Outcome> {
        if let Some(&new_id) = sec_map.get(&target_sec_idx) {
            let sym_id = out.section_symbol(new_id);
            return Ok(Outcome::Internal { sym_id, addend_extra: 0 });
        }
        let (vaddr, key) = if let Some(&v) = section_base_vaddr.get(&target_sec_idx) {
            v
        } else {
            let v = compute_section_base_vaddr(src, target_sec_idx, base, tu_id)
                .with_context(|| {
                    format!(
                        "reloc from {from_section} into pruned section #{}",
                        target_sec_idx.0
                    )
                })?;
            section_base_vaddr.insert(target_sec_idx, v);
            v
        };
        Ok(Outcome::Anchor { vaddr, key, verify_name: None })
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

#[allow(clippy::large_enum_variant)]
enum Outcome {
    Internal { sym_id: SymbolId, addend_extra: i64 },
    /// Resolved against base. The reloc gets rewritten to a per-target
    /// `__graft_assumed_<hex>` SHN_ABS anchor at `vaddr`. `key` is the
    /// dedup identifier for that anchor — stable across rebuilds:
    ///   - for named-symbol resolutions (`base_symtab` lookup or
    ///     `by_symhash` content-match): `key = blake3(name)[..16]`
    ///     (or the symhash for `by_symhash` hits — content-keyed).
    ///   - for STT_SECTION resolutions: the surrogate symbol's
    ///     symhash.
    /// `verify_name = Some(name)` for named-symbol resolutions —
    /// overlay tracks these and post-link checks that the linker put
    /// `name` at `vaddr`. `None` for section anchors (no name to
    /// look up).
    Anchor {
        vaddr: i64,
        key: [u8; 16],
        verify_name: Option<String>,
    },
}

fn compute_section_base_vaddr(
    src: &object::File<'_>,
    target_sec_idx: SectionIndex,
    base: &BaseResolver<'_>,
    tu_id: [u8; 8],
) -> Result<(i64, crate::hash::Symhash)> {
    // Pick the lowest-addressed named, non-File/Section symbol defined
    // in the section. Resolve it through `base`. Subtract the surrogate's
    // offset within the section to get the section start in base's
    // address space. Return the surrogate's symhash too so the caller
    // can use it as a content-stable dedup key for the SHN_ABS anchor.
    let mut best: Option<(u64, &str, bool)> = None;
    for sym in src.symbols() {
        if sym.section_index() != Some(target_sec_idx) {
            continue;
        }
        if matches!(sym.kind(), SymbolKind::File | SymbolKind::Section) {
            continue;
        }
        let name = sym.name().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let was_local =
            matches!(sym.scope(), SymbolScope::Compilation | SymbolScope::Unknown);
        let addr = sym.address();
        if best.map_or(true, |(b, _, _)| addr < b) {
            best = Some((addr, name, was_local));
        }
    }
    let (off, name, was_local) = best.ok_or_else(|| {
        anyhow!(
            "no named surrogate symbol in pruned section #{} — anonymous-only sections \
             are not yet supported by the SHN_ABS path",
            target_sec_idx.0,
        )
    })?;
    let (sh, surrogate_vaddr) = base.resolve(name, was_local, tu_id).ok_or_else(|| {
        anyhow!(
            "surrogate {name} (local={was_local}) for pruned section #{} not in base",
            target_sec_idx.0,
        )
    })?;
    Ok((surrogate_vaddr as i64 - off as i64, sh))
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
