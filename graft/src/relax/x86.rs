//! x86-64 target for the walk's verify-identity mode (docs/16 §8).
//!
//! x86 GNU ld never resizes section interiors, so the walk degenerates
//! to a byte-compare modulo relocation fields: every input section is
//! one byte-granular [`RegionKind::Data`] region and the ISA hooks are
//! all inert. What it buys us: positional resolution upgrades from
//! trusted to verified — the compare proves the section ended up where
//! the section table says, byte-for-byte.
//!
//! The only subtlety is the mask. ld's in-place relaxations rewrite
//! instruction bytes *before* the relocation offset (elf64-x86-64.c
//! `elf_x86_64_convert_load_reloc`): GOTPCRELX-family turns
//! `mov foo@GOTPCREL(%rip)` into `lea`/immediate forms (opcode + modrm
//! at off−2..off, REX at off−3) and `call/jmp *foo@GOT` into direct
//! calls (opcode at off−2); GOTTPOFF (IE→LE) rewrites the same window;
//! TLSGD/TLSLD (GD/LD→IE/LE) rewrite the whole 12–16 byte sequence
//! around the site.

use super::engine::Target;
use super::{InputSection, RegionKind};
use object::elf;

pub struct X86;

impl Target for X86 {
    fn insn_len(&self, _: u8) -> Option<usize> {
        None // variable-length ISA; no insn model needed for verify
    }

    fn free_bits(&self, _: &[u8]) -> [u8; 3] {
        [0; 3]
    }

    fn narrow_ok(&self, _: &[u8], _: &[u8], _: bool) -> bool {
        false
    }

    fn widen_ok(&self, _: &[u8], _: &[u8], _: bool) -> bool {
        false
    }

    fn longcall(&self, _: &[u8], _: &[u8]) -> Option<(usize, usize, bool)> {
        None
    }

    fn nop_len(&self, _: &[u8]) -> Option<usize> {
        None
    }
}

/// Masked byte window for one relocation: (start, len).
fn mask_window(r_type: u32, off: usize) -> (usize, usize) {
    match r_type {
        elf::R_X86_64_64
        | elf::R_X86_64_PC64
        | elf::R_X86_64_GOT64
        | elf::R_X86_64_GOTOFF64
        | elf::R_X86_64_GOTPC64
        | elf::R_X86_64_GOTPCREL64
        | elf::R_X86_64_PLTOFF64
        | elf::R_X86_64_DTPOFF64
        | elf::R_X86_64_TPOFF64
        | elf::R_X86_64_SIZE64 => (off, 8),
        elf::R_X86_64_8 | elf::R_X86_64_PC8 => (off, 1),
        elf::R_X86_64_16 | elf::R_X86_64_PC16 => (off, 2),
        // in-place load conversion: REX + opcode + modrm + field. ld
        // converts mov→lea for *plain* GOTPCREL loads as well, not
        // just the X-suffixed relaxable forms (seen on libstd:
        // `mov foo@GOTPCREL(%rip)` with r_type 9 rewritten to lea).
        // (43 = R_X86_64_CODE_4_GOTPCRELX, not yet in object's consts)
        elf::R_X86_64_GOTPCREL
        | elf::R_X86_64_GOTPCRELX
        | elf::R_X86_64_REX_GOTPCRELX
        | 43
        | elf::R_X86_64_GOTTPOFF => (off.saturating_sub(3), 7),
        // GD/LD → IE/LE rewrites the full model sequence
        elf::R_X86_64_TLSGD | elf::R_X86_64_TLSLD => (off.saturating_sub(4), 16),
        // everything else is a 4-byte field (PC32, 32, 32S, PLT32,
        // GOTPCREL, TPOFF32, DTPOFF32, ...)
        _ => (off, 4),
    }
}

/// Build the walk input for an x86-64 section: bytes plus reloc masks,
/// the whole section as one byte-granular region.
pub fn extract_input(sec: &object::Section) -> Result<InputSection, String> {
    use object::{ObjectSection, RelocationFlags};

    let bytes = sec.data().map_err(|e| e.to_string())?.to_vec();
    let mut mask = vec![false; bytes.len()];
    for (off, rel) in sec.relocations() {
        let r_type = match rel.flags() {
            RelocationFlags::Elf { r_type } => r_type,
            _ => 0,
        };
        let (start, len) = mask_window(r_type, off as usize);
        for m in mask.iter_mut().skip(start).take(len) {
            *m = true;
        }
    }
    let len = bytes.len();
    Ok(InputSection {
        bytes,
        mask,
        regions: vec![(0..len, RegionKind::Data)],
        flex_points: Default::default(),
        lit_expect: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gotpcrelx_masks_opcode_bytes_backward() {
        // mov foo@GOTPCREL(%rip),%rax = 48 8b 05 <disp32>, reloc at +3:
        // the mov→lea rewrite touches 8b, the REX may be re-encoded
        let (s, l) = mask_window(elf::R_X86_64_REX_GOTPCRELX, 3);
        assert_eq!((s, l), (0, 7));
        // plain field reloc masks the field only
        let (s, l) = mask_window(elf::R_X86_64_PC32, 3);
        assert_eq!((s, l), (3, 4));
        let (s, l) = mask_window(elf::R_X86_64_64, 8);
        assert_eq!((s, l), (8, 8));
    }
}
