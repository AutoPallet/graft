//! Per-architecture trampoline encoding. The only target-specific code
//! in graft — picked at combine time based on the base ELF's
//! `e_machine`. Always emits the long form (no narrow/short variants);
//! simplicity over a few saved bytes.

use anyhow::{Result, bail};
use object::elf;

/// Encode a trampoline that, when executed at `from`, transfers control
/// to `to`. The first byte of the returned slice is the entry point —
/// callers must place it at `from` exactly.
pub fn trampoline(machine: u16, from: u64, to: u64) -> Result<Vec<u8>> {
    match machine {
        elf::EM_X86_64 => x86_64_jmp_rel32(from, to),
        elf::EM_XTENSA => xtensa_skip_then_load(to),
        m => bail!("trampoline not implemented for e_machine={m:#x}"),
    }
}

/// Number of bytes the trampoline occupies — callers can validate that
/// the patch site is at least this large before committing.
pub fn trampoline_size(machine: u16) -> Result<usize> {
    match machine {
        elf::EM_X86_64 => Ok(5),
        elf::EM_XTENSA => Ok(14),
        m => bail!("trampoline size not implemented for e_machine={m:#x}"),
    }
}

/// x86-64: `jmp rel32` is 5 bytes, ±2 GB range. The instruction's PC
/// after it executes is `from + 5`, which is what `rel32` is measured
/// against.
fn x86_64_jmp_rel32(from: u64, to: u64) -> Result<Vec<u8>> {
    // i128 to dodge the u64→i64-wraps-at-high-half pitfall: typical
    // overlay addrs are well below 2^63 but it's cheap to be precise.
    let rel: i128 = (to as i128) - (from as i128 + 5);
    if !(i32::MIN as i128..=i32::MAX as i128).contains(&rel) {
        bail!("trampoline target {to:#x} from {from:#x} exceeds rel32 range: {rel:+#x}");
    }
    let mut out = Vec::with_capacity(5);
    out.push(0xe9);
    out.extend_from_slice(&(rel as i32).to_le_bytes());
    Ok(out)
}

/// Xtensa LX7: skip-then-load form, 14 bytes total. Layout when placed
/// at address `from` (`from` must be 4-byte aligned):
///
///   from+0  : `j skip`        (3 bytes)  — encoded `06 01 00`
///   from+3  : pad              (1 byte)
///   from+4  : `.word to`       (4 bytes, LE) — the literal we load
///   from+8  : `l32r a8, [from+4]` (3 bytes) — encoded `81 FF FF`
///   from+11 : `jx a8`          (3 bytes)  — encoded `a0 08 00`
///
/// Three of those four instructions are constant — the only variable
/// is the 32-bit literal. Verified end-to-end against
/// `xtensa-esp32s3-elf-as` output.
///
/// Reach is unbounded (any 32-bit address), so this works regardless of
/// where overlay lands relative to base. Direct `j rel18` would be
/// shorter but the ±128 KB range can't be relied on once base.text grows
/// past ~120 KB or overlay is offset by more than a few KB; one form
/// for both cases keeps the encoder trivial.
fn xtensa_skip_then_load(to: u64) -> Result<Vec<u8>> {
    if to > u64::from(u32::MAX) {
        bail!("xtensa trampoline target {to:#x} doesn't fit in 32 bits");
    }
    let mut out = Vec::with_capacity(14);
    out.extend_from_slice(&[0x06, 0x01, 0x00]); // j +4 → from+8
    out.push(0x00); // pad to 4-byte boundary for the literal
    out.extend_from_slice(&(to as u32).to_le_bytes()); // .word to
    out.extend_from_slice(&[0x81, 0xff, 0xff]); // l32r a8, [from+4]
    out.extend_from_slice(&[0xa0, 0x08, 0x00]); // jx a8
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_jmp_forward() {
        let bytes = trampoline(elf::EM_X86_64, 0x1000, 0x1100).unwrap();
        // jmp rel32: 0xe9 then (0x1100 - 0x1000 - 5) = 0xfb LE.
        assert_eq!(bytes, [0xe9, 0xfb, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn x86_64_jmp_backward() {
        let bytes = trampoline(elf::EM_X86_64, 0x1100, 0x1000).unwrap();
        // rel = -(0x1100 + 5 - 0x1000) = -(0x105) = 0xfffffefb LE.
        assert_eq!(bytes, [0xe9, 0xfb, 0xfe, 0xff, 0xff]);
    }

    #[test]
    fn x86_64_too_far() {
        // 4 GB > 2 GB rel32 reach. Fails cleanly.
        assert!(trampoline(elf::EM_X86_64, 0, 0x1_0000_0000).is_err());
        // u64 high bits: should also fail rather than silently wrap.
        assert!(trampoline(elf::EM_X86_64, 0, u64::MAX - 1).is_err());
    }

    #[test]
    fn xtensa_known_bytes() {
        // Cross-checked against `xtensa-esp32s3-elf-as` of the same
        // sequence with .word 0xDEADBEEF.
        let bytes = trampoline(elf::EM_XTENSA, 0x4201_0000, 0xDEAD_BEEF).unwrap();
        assert_eq!(
            bytes,
            [
                0x06, 0x01, 0x00, // j +4
                0x00, // pad
                0xef, 0xbe, 0xad, 0xde, // .word 0xDEADBEEF
                0x81, 0xff, 0xff, // l32r a8, [from+4]
                0xa0, 0x08, 0x00, // jx a8
            ]
        );
    }

    #[test]
    fn xtensa_size() {
        assert_eq!(trampoline_size(elf::EM_XTENSA).unwrap(), 14);
    }
}
