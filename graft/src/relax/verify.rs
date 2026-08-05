//! Placement verification: does the linked image's content at a
//! claimed address actually correspond to this input section?
//!
//! This is the production face of the walk (docs/16 §8). The map (or
//! the section table derived from it) *claims* "input section S landed
//! at vaddr A, size N"; the only check that claim ever gets is byte
//! matching — masked compare first (O(n), the overwhelmingly common
//! case), and on relaxing targets the transform walk as the slow path.
//! No symbol cross-checks: a wrong attribution puts bytes at the
//! address that don't reconcile, and the claim is refused.
//!
//! Used at BASE time (sweep every attributed section before recording
//! it in `.graft.sections`) and at OVERLAY time (the lazy walk that
//! verifies and — on xtensa — translates interior offsets for
//! channel-2 positional anchors).

use std::collections::HashMap;

use object::{Object, ObjectSection, ObjectSymbol};

use super::{InputSection, Verdict, engine, x86, xtensa};

/// Read-only view of a linked ELF's placed bytes, addressable by vaddr.
/// Built from section headers (every SHF_ALLOC PROGBITS section knows
/// its address and file bytes); NOBITS sections have no bytes and are
/// deliberately absent — callers must not byte-check them.
pub struct LinkedImage<'a> {
    /// (vaddr, bytes), sorted by vaddr.
    secs: Vec<(u64, &'a [u8])>,
}

impl<'a> LinkedImage<'a> {
    pub fn new(elf_bytes: &'a [u8]) -> Result<Self, String> {
        let elf = object::File::parse(elf_bytes).map_err(|e| e.to_string())?;
        let mut secs: Vec<(u64, &'a [u8])> = Vec::new();
        for sec in elf.sections() {
            if sec.address() == 0 || sec.size() == 0 {
                continue; // non-alloc (incl. graft's own metadata sections)
            }
            if let Ok(data) = sec.data()
                && !data.is_empty()
            {
                secs.push((sec.address(), data));
            }
        }
        secs.sort_unstable_by_key(|&(a, _)| a);
        Ok(LinkedImage { secs })
    }

    /// The placed bytes at `[addr, addr+len)`, or `None` if the range
    /// isn't backed by file bytes (NOBITS, out of image).
    pub fn slice(&self, addr: u64, len: u64) -> Option<&'a [u8]> {
        if len == 0 {
            return Some(&[]);
        }
        let i = self.secs.partition_point(|&(a, _)| a <= addr).checked_sub(1)?;
        let (a, data) = self.secs[i];
        let off = (addr - a) as usize;
        let end = off.checked_add(len as usize)?;
        (end <= data.len()).then(|| &data[off..end])
    }
}

/// Names defined at exactly one address in the linked image — the
/// resolution source for literal value pins (`InputSection::
/// lit_expect`), which keep a reloc-masked pool word from matching
/// arbitrary output bytes during the walk (docs/16 §4).
pub fn unique_symbol_addrs(elf: &object::File) -> HashMap<String, u64> {
    let mut out: HashMap<String, u64> = HashMap::new();
    let mut ambiguous: std::collections::HashSet<String> = Default::default();
    for sym in elf.symbols() {
        if sym.is_undefined()
            || matches!(sym.kind(), object::SymbolKind::Section | object::SymbolKind::File)
        {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        match out.entry(name.to_string()) {
            std::collections::hash_map::Entry::Occupied(e) => {
                if *e.get() != sym.address() {
                    ambiguous.insert(name.to_string());
                }
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(sym.address());
            }
        }
    }
    for name in &ambiguous {
        out.remove(name);
    }
    out
}

/// Build the walk's input-side view of one section, dispatched by
/// architecture. `lit_syms` feeds xtensa literal value pins and is
/// ignored elsewhere. The non-xtensa arm uses the x86 extractor: graft
/// only links x86-64 and xtensa, and the x86 view (whole section as
/// byte-granular data, reloc-window masks) is the right degenerate
/// shape for any non-relaxing target.
pub fn input_view(
    arch: object::Architecture,
    file: &object::File,
    sec: &object::Section,
    lit_syms: &HashMap<String, u64>,
) -> Result<InputSection, String> {
    match arch {
        object::Architecture::Xtensa => xtensa::extract_input(file, sec, lit_syms),
        _ => x86::extract_input(sec),
    }
}

/// Outcome of checking one placement claim.
pub enum SectionCheck {
    /// Placed bytes equal the input modulo reloc fields.
    Identical,
    /// xtensa: bytes differ but every difference is explained by ld's
    /// transform alphabet (relaxation) — placement claim holds, but
    /// interior offsets need fate translation before use.
    Reconciled,
    /// Bytes at the claimed address do not correspond to this input
    /// section. The claim must be refused, never used.
    Dirty(String),
}

/// Check one placement claim: masked compare, then (xtensa only) the
/// transform walk. A walk that leans on diagnostic rules (`Census::
/// diagnostics`) is NOT source-grounded and counts as dirty — base's
/// corpus reconciles with zero diagnostic uses, so any use marks a
/// section we don't actually understand.
pub fn check_section(
    arch: object::Architecture,
    input: &InputSection,
    out: &[u8],
) -> SectionCheck {
    let runs = match engine::masked_compare(input, out) {
        Ok(()) => return SectionCheck::Identical,
        Err(runs) => runs,
    };
    if arch == object::Architecture::Xtensa {
        return match engine::reconcile(input, out, &xtensa::Xtensa) {
            Verdict::Reconciled(c) if c.diagnostics() == 0 => SectionCheck::Reconciled,
            Verdict::Reconciled(c) => SectionCheck::Dirty(format!(
                "walk needed {} non-source diagnostic rule uses",
                c.diagnostics()
            )),
            Verdict::Dirty(_, runs) => {
                let desc: Vec<String> = runs
                    .iter()
                    .take(4)
                    .map(|r| format!("({},{},{})", r.in_off, r.in_len, r.out_len))
                    .collect();
                SectionCheck::Dirty(format!("walk dirty runs {}", desc.join(" ")))
            }
            Verdict::Refused(why) => SectionCheck::Dirty(format!("walk refused: {why}")),
        };
    }
    let desc: Vec<String> = runs
        .iter()
        .take(4)
        .map(|r| format!("({},{},{})", r.in_off, r.in_len, r.out_len))
        .collect();
    SectionCheck::Dirty(format!("masked compare runs {}", desc.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linked_image_slices_by_vaddr() {
        // Hand-rolled: LinkedImage over synthetic sections isn't easy to
        // construct without an ELF; test the slice arithmetic directly.
        let a = [1u8, 2, 3, 4];
        let b = [9u8, 8, 7];
        let img = LinkedImage { secs: vec![(0x1000, &a[..]), (0x2000, &b[..])] };
        assert_eq!(img.slice(0x1000, 4), Some(&a[..]));
        assert_eq!(img.slice(0x1001, 2), Some(&a[1..3]));
        assert_eq!(img.slice(0x1001, 4), None); // crosses the section end
        assert_eq!(img.slice(0x2002, 1), Some(&b[2..3]));
        assert_eq!(img.slice(0x3000, 1), None);
        assert_eq!(img.slice(0x0500, 1), None);
        assert_eq!(img.slice(0x9999, 0), Some(&[][..]));
    }

    #[test]
    fn check_section_identical_and_dirty() {
        let input = InputSection {
            bytes: vec![0xAA, 0xBB, 0xCC, 0xDD],
            mask: vec![false, true, false, false],
            regions: vec![(0..4, crate::relax::RegionKind::Data)],
            flex_points: Default::default(),
            longcall_points: Default::default(),
            lit_expect: Default::default(),
        };
        // masked byte differs → still identical
        assert!(matches!(
            check_section(object::Architecture::X86_64, &input, &[0xAA, 0x00, 0xCC, 0xDD]),
            SectionCheck::Identical
        ));
        // unmasked byte differs → dirty on a non-relaxing target
        assert!(matches!(
            check_section(object::Architecture::X86_64, &input, &[0xAA, 0x00, 0xCC, 0xDE]),
            SectionCheck::Dirty(_)
        ));
    }
}
