//! Synthetic "base map" object: anchor definitions for the overlay link.
//!
//! Prune emits every base-bound reloc as an UND reference to
//! `__graft_assumed_<vaddr>`; this module synthesizes the single ET_REL
//! object that *defines* those names. The encoding rule (docs/worklogs/15):
//!
//!   - vaddr inside a base PT_LOAD → ordinary symbol defined inside a
//!     NOBITS map section placed (by layout script / `--section-start`)
//!     at the base address span it mirrors. Positional content is
//!     *image-relative*, and a section-defined symbol is ELF's way of
//!     saying that — under a future `-pie` overlay link these resolve
//!     correctly, where SHN_ABS would silently lose the load bias.
//!   - vaddr inside base's PT_TLS template → symbol in an SHF_TLS map
//!     section: ld rebuilds an identical-geometry PT_TLS and recomputes
//!     TP offsets itself (graft owns no tpoff arithmetic).
//!   - vaddr outside every PT_LOAD → SHN_ABS. True constants (esp32
//!     ROM/PROVIDE addresses) are the one thing ABS is *for*.
//!
//! Map sections mirror base's layout *minus the slack carve-outs*
//! (overlay content is placed inside those, and output sections must
//! not overlap) and minus the PT_TLS span (covered by the TLS maps).
//! All symbols are STB_GLOBAL + STV_HIDDEN: global so UND references
//! in pruned objects bind to them, hidden to document they must
//! resolve within this link.
//!
//! The map carries no loadable content: combine skips `.graft.map.*`
//! by name (and most are NOBITS anyway). The one PROGBITS exception is
//! the pre-hole TLS map — PT_TLS file-offset layout forbids PROGBITS
//! after NOBITS, and re-emitted `.tdata` in the slack hole is PROGBITS.

use anyhow::{Context, Result, bail};
use object::{
    Architecture, BinaryFormat, Endianness, SectionKind, SymbolKind,
    write::{Object as WObject, Symbol as WSymbol, SymbolSection},
};

/// Base's PT_TLS template span plus the in-template slack hole where
/// re-emitted / new TLS sections land. All fields are template vaddrs
/// (`PT_TLS.p_vaddr`-based, matching the section table's TLS entries).
#[derive(Debug, Clone, Copy)]
pub struct TlsMapSpec {
    pub start: u64,
    pub end: u64,
    pub hole_start: u64,
    pub hole_end: u64,
    /// Base PT_TLS p_align — the pre-hole map section carries it so the
    /// overlay's PT_TLS reproduces base's alignment (TP offsets depend
    /// on `align_up(memsz, align)`).
    pub align: u64,
}

/// One map output section the linker must place at a fixed address.
#[derive(Debug, Clone)]
pub struct MapSection {
    pub name: String,
    pub vaddr: u64,
    /// GC-root symbol defined at the section's offset 0. The overlay
    /// link runs with `--gc-sections`, and map sections must survive
    /// even when no live reloc references them — the TLS maps carry
    /// PT_TLS *geometry* (memsz/align), which matters even if every
    /// TLS reference resolves to a re-emitted copy. Passed as
    /// `-Wl,--undefined=` (the same trick the slack sections use).
    pub keep_symbol: String,
}

#[derive(Debug)]
pub struct BaseMap {
    pub object_bytes: Vec<u8>,
    /// Placement list for the layout script / `--section-start` flags.
    pub sections: Vec<MapSection>,
}

/// Synthesize the base-map object.
///
/// `anchors`: deduped `(vaddr, tls)` across all pruned objects.
/// `loads`: base's PT_LOAD spans `(vaddr, memsz)`.
/// `carve_outs`: address ranges map sections must not cover — the
/// slack regions (overlay content lands there) and the PT_TLS span
/// (covered by the TLS maps instead).
/// `tls`: present iff the overlay link involves TLS at all (TLS
/// anchors, or re-emitted TLS sections that need the template
/// geometry around them).
pub fn synthesize(
    arch: Architecture,
    anchors: &[(u64, bool)],
    loads: &[(u64, u64)],
    carve_outs: &[(u64, u64)],
    tls: Option<TlsMapSpec>,
) -> Result<BaseMap> {
    let mut obj = WObject::new(BinaryFormat::Elf, arch, Endianness::Little);
    let mut placements: Vec<MapSection> = Vec::new();

    // Non-TLS intervals: each PT_LOAD span minus every carve-out,
    // sorted; only intervals that contain at least one anchor become
    // sections (a segment nobody anchors into needs no map).
    let mut intervals: Vec<(u64, u64)> = Vec::new();
    for &(start, memsz) in loads {
        let mut pieces = vec![(start, start + memsz)];
        for &(c_start, c_len) in carve_outs {
            let c_end = c_start + c_len;
            let mut next = Vec::new();
            for (s, e) in pieces {
                if c_end <= s || c_start >= e {
                    next.push((s, e));
                } else {
                    if c_start > s {
                        next.push((s, c_start));
                    }
                    if c_end < e {
                        next.push((c_end, e));
                    }
                }
            }
            pieces = next;
        }
        intervals.extend(pieces);
    }
    intervals.sort_unstable();

    let in_tls = |v: u64| tls.is_some_and(|t| v >= t.start && v < t.end);

    // Bucket anchors: per-interval, TLS, or ABS (outside everything).
    let mut by_interval: Vec<Vec<u64>> = vec![Vec::new(); intervals.len()];
    let mut tls_anchors: Vec<u64> = Vec::new();
    let mut abs_anchors: Vec<u64> = Vec::new();
    for &(vaddr, is_tls) in anchors {
        if is_tls {
            let Some(t) = tls else {
                bail!("TLS anchor {vaddr:#x} but no TLS map spec (base has no PT_TLS?)");
            };
            if vaddr >= t.hole_start && vaddr < t.hole_end {
                bail!(
                    "TLS anchor {vaddr:#x} lands inside the TLS slack hole \
                     ({:#x}..{:#x}) — base content can't live in slack",
                    t.hole_start,
                    t.hole_end
                );
            }
            if !in_tls(vaddr) {
                bail!(
                    "anchor {vaddr:#x} classified TLS but outside base's PT_TLS \
                     span ({:#x}..{:#x})",
                    t.start,
                    t.end
                );
            }
            tls_anchors.push(vaddr);
            continue;
        }
        match intervals.iter().position(|&(s, e)| vaddr >= s && vaddr < e) {
            Some(i) => by_interval[i].push(vaddr),
            None => {
                // Inside a PT_LOAD but carved out would mean an anchor
                // into slack — base content never lives there.
                let in_load = loads.iter().any(|&(s, m)| vaddr >= s && vaddr < s + m);
                if in_load {
                    bail!(
                        "anchor {vaddr:#x} lands inside a carve-out (slack/TLS) \
                         region — base content can't live there"
                    );
                }
                abs_anchors.push(vaddr);
            }
        }
    }

    let hidden = object::write::SymbolScope::Linkage; // STB_GLOBAL + STV_HIDDEN
    let add_keep = |obj: &mut WObject, sec, suffix: &str, tls: bool| -> String {
        let keep = format!("__graft_map_keep_{suffix}");
        obj.add_symbol(WSymbol {
            name: keep.clone().into_bytes(),
            value: 0,
            size: 0,
            kind: if tls { SymbolKind::Tls } else { SymbolKind::Label },
            scope: hidden,
            weak: false,
            section: SymbolSection::Section(sec),
            flags: object::write::SymbolFlags::None,
        });
        keep
    };

    let mut map_idx = 0usize;
    for (i, &(s, e)) in intervals.iter().enumerate() {
        if by_interval[i].is_empty() {
            continue;
        }
        let name = format!(".graft.map.{map_idx}");
        let sec = obj.add_section(Vec::new(), name.clone().into_bytes(), SectionKind::UninitializedData);
        // align 1: the script/--section-start pins the exact address;
        // any larger alignment could shift it.
        obj.section_mut(sec).append_bss(e - s, 1);
        for &vaddr in &by_interval[i] {
            obj.add_symbol(WSymbol {
                name: format!("__graft_assumed_{vaddr:016x}").into_bytes(),
                value: vaddr - s,
                size: 0,
                kind: SymbolKind::Label,
                scope: hidden,
                weak: false,
                section: SymbolSection::Section(sec),
                flags: object::write::SymbolFlags::None,
            });
        }
        let keep_symbol = add_keep(&mut obj, sec, &map_idx.to_string(), false);
        map_idx += 1;
        placements.push(MapSection { name, vaddr: s, keep_symbol });
    }

    // TLS maps: pre-hole PROGBITS-zeros (so re-emitted PROGBITS .tdata
    // in the hole never follows NOBITS within PT_TLS), post-hole
    // NOBITS reaching exactly to base's template end (overlay memsz
    // must equal base's — TP offsets are end-anchored).
    if let Some(t) = tls {
        if !(t.start <= t.hole_start && t.hole_start <= t.hole_end && t.hole_end <= t.end) {
            bail!(
                "TLS map spec out of order: start {:#x} hole {:#x}..{:#x} end {:#x}",
                t.start,
                t.hole_start,
                t.hole_end,
                t.end
            );
        }
        if t.hole_end == t.end {
            // With nothing after the hole, the overlay template would
            // end wherever the hole's content ends — memsz (and with
            // it every TP offset) would silently differ from base's.
            bail!(
                "TLS slack sits at the very end of base's template — \
                 unsupported (overlay PT_TLS memsz could not be pinned \
                 to base's). Base must have at least one .tbss byte \
                 after the slack."
            );
        }
        let pre = obj.add_section(Vec::new(), b".graft.map.tls0".to_vec(), SectionKind::Tls);
        obj.set_section_data(pre, vec![0u8; (t.hole_start - t.start) as usize], t.align);
        let keep0 = add_keep(&mut obj, pre, "tls0", true);
        placements.push(MapSection {
            name: ".graft.map.tls0".into(),
            vaddr: t.start,
            keep_symbol: keep0,
        });

        let post = obj.add_section(
            Vec::new(),
            b".graft.map.tls1".to_vec(),
            SectionKind::UninitializedTls,
        );
        obj.section_mut(post).append_bss(t.end - t.hole_end, 1);
        let keep1 = add_keep(&mut obj, post, "tls1", true);
        placements.push(MapSection {
            name: ".graft.map.tls1".into(),
            vaddr: t.hole_end,
            keep_symbol: keep1,
        });

        for vaddr in tls_anchors {
            let (sec, base) = if vaddr < t.hole_start { (pre, t.start) } else { (post, t.hole_end) };
            obj.add_symbol(WSymbol {
                name: format!("__graft_assumed_{vaddr:016x}").into_bytes(),
                value: vaddr - base,
                size: 0,
                kind: SymbolKind::Tls,
                scope: hidden,
                weak: false,
                section: SymbolSection::Section(sec),
                flags: object::write::SymbolFlags::None,
            });
        }
    } else if !tls_anchors.is_empty() {
        bail!("TLS anchors present but no TLS map spec");
    }

    // True constants: addresses outside every PT_LOAD (esp32 ROM,
    // PROVIDE absolutes). SHN_ABS is exactly what these mean — they
    // never relocate with the image.
    for vaddr in abs_anchors {
        obj.add_symbol(WSymbol {
            name: format!("__graft_assumed_{vaddr:016x}").into_bytes(),
            value: vaddr,
            size: 0,
            kind: SymbolKind::Label,
            scope: hidden,
            weak: false,
            section: SymbolSection::Absolute,
            flags: object::write::SymbolFlags::None,
        });
    }

    let object_bytes = obj.write().context("emit base-map object")?;
    Ok(BaseMap { object_bytes, sections: placements })
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::{Object, ObjectSection, ObjectSymbol};

    fn find_sym<'a>(
        f: &'a object::File<'a>,
        name: &str,
    ) -> object::Symbol<'a, 'a> {
        f.symbols()
            .find(|s| s.name().unwrap_or("") == name)
            .unwrap_or_else(|| panic!("{name} not in map object"))
    }

    #[test]
    fn anchors_inside_loads_become_section_symbols_split_around_carves() {
        // One load [0x1000, 0x3000), slack carve [0x1800, 0x2000) → two
        // intervals. Anchors land on each side; one anchor is outside
        // every load (ROM) → ABS.
        let map = synthesize(
            Architecture::X86_64,
            &[(0x1010, false), (0x2020, false), (0x4000_0000, false)],
            &[(0x1000, 0x2000)],
            &[(0x1800, 0x800)],
            None,
        )
        .expect("synthesize");
        assert_eq!(map.sections.len(), 2);
        assert_eq!(map.sections[0].vaddr, 0x1000);
        assert_eq!(map.sections[1].vaddr, 0x2000);

        let f = object::File::parse(&*map.object_bytes).unwrap();
        let a = find_sym(&f, "__graft_assumed_0000000000001010");
        assert!(a.section_index().is_some(), "in-load anchor is section-defined");
        assert_eq!(a.address(), 0x10, "offset within the first interval");
        let b = find_sym(&f, "__graft_assumed_0000000000002020");
        assert_eq!(b.address(), 0x20, "offset within the second interval");
        let rom = find_sym(&f, "__graft_assumed_0000000040000000");
        assert!(
            rom.section_index().is_none() && !rom.is_undefined(),
            "out-of-image anchor stays SHN_ABS"
        );
        assert_eq!(rom.address(), 0x4000_0000);
        // Hidden globals: resolvable across objects, never exported.
        assert!(a.is_global() && b.is_global() && rom.is_global());
    }

    #[test]
    fn anchor_in_carve_out_bails() {
        let err = synthesize(
            Architecture::X86_64,
            &[(0x1900, false)],
            &[(0x1000, 0x2000)],
            &[(0x1800, 0x800)],
            None,
        )
        .expect_err("slack anchor must bail");
        assert!(format!("{err:#}").contains("carve-out"));
    }

    #[test]
    fn tls_maps_reproduce_template_geometry() {
        let spec = TlsMapSpec {
            start: 0x7000,
            end: 0x7100,
            hole_start: 0x7040,
            hole_end: 0x7080,
            align: 16,
        };
        let map = synthesize(
            Architecture::X86_64,
            &[(0x7010, true), (0x7090, true)],
            &[(0x6000, 0x4000)],
            &[(0x7000, 0x100)], // TLS span carved from the load
            Some(spec),
        )
        .expect("synthesize");
        let names: Vec<&str> = map.sections.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&".graft.map.tls0"));
        assert!(names.contains(&".graft.map.tls1"));

        let f = object::File::parse(&*map.object_bytes).unwrap();
        let pre = f
            .sections()
            .find(|s| s.name().unwrap_or("") == ".graft.map.tls0")
            .unwrap();
        // Pre-hole map is PROGBITS (file-backed zeros) so re-emitted
        // PROGBITS .tdata in the hole never follows NOBITS in PT_TLS.
        assert_eq!(pre.size(), 0x40);
        assert!(pre.data().map(|d| d.len() == 0x40).unwrap_or(false));
        let post = f
            .sections()
            .find(|s| s.name().unwrap_or("") == ".graft.map.tls1")
            .unwrap();
        assert_eq!(post.size(), 0x80, "post-hole map reaches template end");

        let a = find_sym(&f, "__graft_assumed_0000000000007010");
        assert!(matches!(a.kind(), object::SymbolKind::Tls));
        assert_eq!(a.address(), 0x10);
        let b = find_sym(&f, "__graft_assumed_0000000000007090");
        assert!(matches!(b.kind(), object::SymbolKind::Tls));
        assert_eq!(b.address(), 0x10, "offset within the post-hole map");
    }

    #[test]
    fn tls_anchor_in_hole_bails() {
        let spec = TlsMapSpec {
            start: 0x7000,
            end: 0x7100,
            hole_start: 0x7040,
            hole_end: 0x7080,
            align: 16,
        };
        let err = synthesize(
            Architecture::X86_64,
            &[(0x7050, true)],
            &[],
            &[],
            Some(spec),
        )
        .expect_err("hole anchor must bail");
        assert!(format!("{err:#}").contains("slack hole"));
    }

    #[test]
    fn tls_slack_at_template_end_bails() {
        let spec = TlsMapSpec {
            start: 0x7000,
            end: 0x7100,
            hole_start: 0x70c0,
            hole_end: 0x7100,
            align: 16,
        };
        let err = synthesize(Architecture::X86_64, &[], &[], &[], Some(spec))
            .expect_err("end-of-template slack must bail");
        assert!(format!("{err:#}").contains("very end"));
    }
}
