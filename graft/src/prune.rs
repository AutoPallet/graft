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
//!       by base) get encoded as `(__graft_const, addend = base_vaddr +
//!       original_addend)`. `__graft_const` is a single SHN_ABS=0 symbol
//!       injected per pruned `.o`, so the linker computes
//!       `0 + (base_vaddr + addend) = base_vaddr + addend` directly into
//!       the reloc slot. No PROVIDE() or symbol-name plumbing required.
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
    /// prune time — `wrap_addr_by_name` provides that address.
    pub wrapped: &'a HashSet<String>,
    /// Name → address from base.elf's `.symtab`. Only consulted for
    /// the `__wrap_<sym>` wrap-target lookup (wrap names are stable,
    /// so name-based lookup is safe).
    pub wrap_addr_by_name: &'a HashMap<String, u64>,
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
    /// Count of relocations rewritten to `(__graft_const, base_vaddr + addend)`.
    /// Reported in the overlay summary; useful for diagnosing whether a
    /// closure leans heavily on base resolution vs internal kept-section refs.
    pub abs_rewrites: usize,
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

    // Per-object SHN_ABS=0 anchor for every base-bound reloc. Created
    // lazily so objects with zero base refs don't carry a dead entry.
    let mut const_sym: Option<SymbolId> = None;
    // Cache: target_sec_idx -> base vaddr of section start (i.e. the
    // surrogate's base vaddr minus its offset within the section).
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
                            // Wraps are name-stable: ld would
                            // redirect `<name>` → `__wrap_<name>`.
                            // Pre-apply by name-looking up
                            // `__wrap_<name>` in base.elf's .symtab.
                            if base.wrapped.contains(name) {
                                let wrap_name = format!("__wrap_{name}");
                                let vaddr = base.wrap_addr_by_name.get(&wrap_name).copied().ok_or_else(
                                    || anyhow!(
                                        "reloc in {from_section}: can't resolve wrap target {wrap_name} against base"
                                    ),
                                )?;
                                Outcome::Base { vaddr: vaddr as i64 }
                            } else {
                                // Three-way classification:
                                //   1. Overlay sees this symbol AND
                                //      its symhash is in the closure
                                //      → it's been re-emitted with
                                //      different content; emit UND
                                //      so ld resolves to overlay.
                                //   2. Overlay sees it AND base has
                                //      a matching symhash → SHN_ABS
                                //      to base's address.
                                //   3. Overlay doesn't see it (lazy
                                //      discovery skipped its `.o`)
                                //      → fall back to name lookup
                                //      against base.elf's `.symtab`.
                                //      Safe for stable-named symbols.
                                let overlay_sh = if was_local {
                                    base.overlay_symhash_locals
                                        .get(&(name.to_string(), source_tu_id))
                                        .copied()
                                        .or_else(|| base.overlay_symhash_globals.get(name).copied())
                                        .or_else(|| base.overlay_symhash_locals_any_tu.get(name).copied())
                                } else {
                                    base.overlay_symhash_globals
                                        .get(name)
                                        .copied()
                                        .or_else(|| base.overlay_symhash_locals_any_tu.get(name).copied())
                                };
                                if let Some(sh) = overlay_sh {
                                    if base.closure_symhashes.contains(&sh) {
                                        // Closure-included → UND.
                                        let wsym_id = match wrap_sym_map.get(name) {
                                            Some(&id) => id,
                                            None => {
                                                let id = out.add_symbol(WSymbol {
                                                    name: name.as_bytes().to_vec(),
                                                    value: 0,
                                                    size: 0,
                                                    kind: SymbolKind::Unknown,
                                                    scope: write::SymbolScope::Dynamic,
                                                    weak: false,
                                                    section: WSymbolSection::Undefined,
                                                    flags: write::SymbolFlags::None,
                                                });
                                                wrap_sym_map.insert(name.to_string(), id);
                                                id
                                            }
                                        };
                                        Outcome::Internal { sym_id: wsym_id, addend_extra: 0 }
                                    } else if let Some(entry) = base.by_symhash.get(&sh) {
                                        Outcome::Base { vaddr: entry.address as i64 }
                                    } else {
                                        bail!(
                                            "reloc in {from_section}: {name} (local={was_local}) \
                                             has overlay symhash but no matching base entry — \
                                             content drift but not in closure (graft bug?)"
                                        );
                                    }
                                } else if let Some(&vaddr) = base.wrap_addr_by_name.get(name) {
                                    // Overlay didn't see the symbol
                                    // (e.g. inside a libcore `.o`
                                    // lazy discovery skipped). Trust
                                    // base.elf's `.symtab` by name.
                                    Outcome::Base { vaddr: vaddr as i64 }
                                } else {
                                    bail!(
                                        "reloc in {from_section}: can't resolve {name} \
                                         (local={was_local}) — not in overlay scan or base .symtab"
                                    );
                                }
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
                Outcome::Base { vaddr } => {
                    abs_rewrites += 1;
                    let csym = match const_sym {
                        Some(id) => id,
                        None => {
                            let id = out.add_symbol(WSymbol {
                                name: b"__graft_const".to_vec(),
                                value: 0,
                                size: 0,
                                kind: SymbolKind::Label, // STT_NOTYPE
                                scope: write::SymbolScope::Compilation, // STB_LOCAL
                                weak: false,
                                section: WSymbolSection::Absolute,
                                flags: write::SymbolFlags::None,
                            });
                            const_sym = Some(id);
                            id
                        }
                    };
                    (csym, vaddr + addend)
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
        section_base_vaddr: &mut HashMap<SectionIndex, i64>,
        base: &BaseResolver<'_>,
        tu_id: [u8; 8],
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
        Ok(Outcome::Base { vaddr })
    }

    let bytes = out.write().map_err(|e| anyhow!("write pruned object: {e}"))?;
    Ok(Pruned {
        bytes,
        kept_sections: sec_map.len(),
        abs_rewrites,
    })
}

#[allow(clippy::large_enum_variant)]
enum Outcome {
    Internal { sym_id: SymbolId, addend_extra: i64 },
    Base { vaddr: i64 },
}

fn compute_section_base_vaddr(
    src: &object::File<'_>,
    target_sec_idx: SectionIndex,
    base: &BaseResolver<'_>,
    tu_id: [u8; 8],
) -> Result<i64> {
    // Pick the lowest-addressed named, non-File/Section symbol defined
    // in the section. Resolve it through `base`. Subtract the surrogate's
    // offset within the section to get the section start in base's
    // address space.
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
    let (_sh, surrogate_vaddr) = base.resolve(name, was_local, tu_id).ok_or_else(|| {
        anyhow!(
            "surrogate {name} (local={was_local}) for pruned section #{} not in base",
            target_sec_idx.0,
        )
    })?;
    Ok(surrogate_vaddr as i64 - off as i64)
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
