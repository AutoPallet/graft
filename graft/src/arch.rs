//! Per-architecture trampoline encoding. The only target-specific code
//! in graft — picked at combine time based on the base ELF's
//! `e_machine`. Always emits the long form (no narrow/short variants);
//! simplicity over a few saved bytes.

use anyhow::{Result, bail};
use object::elf;

/// Encode a trampoline that, when executed at `from`, transfers control
/// to `to`. The first byte of the returned slice is the entry point —
/// callers must place it at `from` exactly.
///
/// `prologue` is the original bytes already at `from`. Most targets
/// ignore it; xtensa needs the first 3 bytes (the windowed-ABI `entry`
/// instruction) preserved so the caller's `call8 main` lands on a valid
/// frame-allocating prologue. The trampoline then jumps past overlay's
/// own entry (which would double-allocate the frame and rotate the
/// window twice). Pass at least `trampoline_prologue_size(machine)`
/// bytes; extras are ignored.
pub fn trampoline(machine: u16, from: u64, to: u64, prologue: &[u8]) -> Result<Vec<u8>> {
    match machine {
        elf::EM_X86_64 => x86_64_jmp_rel32(from, to),
        elf::EM_XTENSA => xtensa_skip_then_load(to, prologue),
        m => bail!("trampoline not implemented for e_machine={m:#x}"),
    }
}

/// Total trampoline byte length including any preserved prologue.
pub fn trampoline_size(machine: u16) -> Result<usize> {
    match machine {
        elf::EM_X86_64 => Ok(5),
        elf::EM_XTENSA => Ok(18),
        m => bail!("trampoline size not implemented for e_machine={m:#x}"),
    }
}

/// How many bytes of the existing function the trampoline copies
/// verbatim (then continues with arch-specific redirect). 0 on most
/// targets; 3 on xtensa for the `entry` instruction.
pub fn trampoline_prologue_size(machine: u16) -> Result<usize> {
    match machine {
        elf::EM_X86_64 => Ok(0),
        elf::EM_XTENSA => Ok(3),
        m => bail!("trampoline prologue not implemented for e_machine={m:#x}"),
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

/// Xtensa LX7: preserve-entry skip-then-load, 18 bytes total. Layout
/// when placed at address `from` (`from` must be 4-byte aligned):
///
///   from+0  : <prologue[0..3]> — the original `entry aN, FRAME` (3 bytes)
///   from+3  : `j skip`                 (3 bytes)  — encoded `46 01 00`
///   from+6  : pad                       (2 bytes)
///   from+8  : `.word (to + 3)`          (4 bytes, LE) — *target+3* skips
///                                                       overlay's own
///                                                       `entry` so we
///                                                       don't allocate
///                                                       a second frame
///                                                       on top of the
///                                                       caller's
///                                                       `call8 main`.
///   from+12 : `l32r a8, [from+8]`       (3 bytes)  — encoded `81 FF FF`
///   from+15 : `jx a8`                   (3 bytes)  — encoded `a0 08 00`
///
/// Why preserve the entry: Xtensa's windowed-register ABI has the
/// caller execute `call8 callee`, which advances the register window
/// by 8 and stashes the return address. The callee's first instruction
/// must be `entry aN, FRAME`, which allocates `FRAME` bytes of stack
/// and confirms the new window. Skipping or duplicating `entry` corrupts
/// the window state — the chip silently hangs after the first call.
///
/// Constraint: overlay's function must allocate the same stack frame
/// as base's (typically true for "same Rust source, same compiler").
/// If frame sizes diverge, the windowed-ABI assumption breaks; that's
/// a future concern (likely needs the trampoline to allocate the larger
/// frame, or to use a non-windowed call sequence).
///
/// Verified bytes via `xtensa-esp32s3-elf-as` for the constant-encoded
/// portions. `entry`'s exact bytes are read from the live base ELF.
fn xtensa_skip_then_load(to: u64, prologue: &[u8]) -> Result<Vec<u8>> {
    if to > u64::from(u32::MAX) {
        bail!("xtensa trampoline target {to:#x} doesn't fit in 32 bits");
    }
    if prologue.len() < 3 {
        bail!(
            "xtensa trampoline needs >= 3 bytes of prologue (the entry instruction); got {}",
            prologue.len()
        );
    }
    // Sanity: entry instruction's 6-bit opcode (bits[3:0]=0x6, bits[5:4]=0x3
    // → byte0 = 0x36) — bail loudly if base's "main" doesn't open with
    // entry, since the windowed-ABI assumption silently breaks otherwise.
    if prologue[0] != 0x36 {
        bail!(
            "expected `entry` instruction at base function start; first byte was {:#04x}",
            prologue[0]
        );
    }
    let target = (to as u32).wrapping_add(3); // skip overlay's own entry
    let mut out = Vec::with_capacity(18);
    out.extend_from_slice(&prologue[..3]); // preserved `entry aN, FRAME`
    out.extend_from_slice(&[0x46, 0x01, 0x00]); // j +5 → from+12 (skip pad+literal)
    out.extend_from_slice(&[0x00, 0x00]); // pad to 4-byte for literal
    out.extend_from_slice(&target.to_le_bytes()); // .word (to + 3)
    out.extend_from_slice(&[0x81, 0xff, 0xff]); // l32r a8, [from+8]
    out.extend_from_slice(&[0xa0, 0x08, 0x00]); // jx a8
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_jmp_forward() {
        let bytes = trampoline(elf::EM_X86_64, 0x1000, 0x1100, &[]).unwrap();
        // jmp rel32: 0xe9 then (0x1100 - 0x1000 - 5) = 0xfb LE.
        assert_eq!(bytes, [0xe9, 0xfb, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn x86_64_jmp_backward() {
        let bytes = trampoline(elf::EM_X86_64, 0x1100, 0x1000, &[]).unwrap();
        // rel = -(0x1100 + 5 - 0x1000) = -(0x105) = 0xfffffefb LE.
        assert_eq!(bytes, [0xe9, 0xfb, 0xfe, 0xff, 0xff]);
    }

    #[test]
    fn x86_64_too_far() {
        // 4 GB > 2 GB rel32 reach. Fails cleanly.
        assert!(trampoline(elf::EM_X86_64, 0, 0x1_0000_0000, &[]).is_err());
        // u64 high bits: should also fail rather than silently wrap.
        assert!(trampoline(elf::EM_X86_64, 0, u64::MAX - 1, &[]).is_err());
    }

    #[test]
    fn xtensa_known_bytes() {
        // `entry a1, 192` = 0x36 0x81 0x01 (cross-checked against
        // xtensa-esp32s3-elf-as).
        let prologue = [0x36, 0x81, 0x01];
        let bytes = trampoline(elf::EM_XTENSA, 0x4201_0000, 0xDEAD_BEEC, &prologue).unwrap();
        // target field stores (to + 3) = 0xDEADBEEF.
        assert_eq!(
            bytes,
            [
                0x36, 0x81, 0x01, // preserved entry a1, 192
                0x46, 0x01, 0x00, // j +5
                0x00, 0x00, // pad
                0xef, 0xbe, 0xad, 0xde, // .word (to + 3)
                0x81, 0xff, 0xff, // l32r a8, [from+8]
                0xa0, 0x08, 0x00, // jx a8
            ]
        );
    }

    #[test]
    fn xtensa_size() {
        assert_eq!(trampoline_size(elf::EM_XTENSA).unwrap(), 18);
        assert_eq!(trampoline_prologue_size(elf::EM_XTENSA).unwrap(), 3);
    }

    #[test]
    fn xtensa_rejects_non_entry_prologue() {
        // First byte must be 0x36 (the `entry` opcode); anything else
        // means the windowed-ABI assumption doesn't hold.
        assert!(trampoline(elf::EM_XTENSA, 0, 0x1234, &[0x12, 0x34, 0x56]).is_err());
    }
}
