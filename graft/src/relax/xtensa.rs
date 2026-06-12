//! xtensa knowledge for the relaxation walk: the narrow/widen pair
//! tables, longcall shape, pc-relative free bits, nop encodings, and
//! `.xt.prop` decoding (docs/16 §§2–4). Transcribed from binutils
//! `bfd/elf32-xtensa.c` at espressif tag `esp-2.45.0_20250920`; every
//! encoding below is pinned by assembled ground truth in the tests.

use super::engine::Target;
use super::{InputSection, RegionKind};
use std::collections::{HashMap, HashSet};

// ---- field helpers (little-endian; insn24 = b0 | b1<<8 | b2<<16) ----

fn insn24(b: &[u8]) -> u32 {
    b[0] as u32 | (b[1] as u32) << 8 | (b[2] as u32) << 16
}

fn insn16(b: &[u8]) -> u32 {
    b[0] as u32 | (b[1] as u32) << 8
}

fn op0(i: u32) -> u32 {
    i & 0xF
}

fn ft(i: u32) -> u32 {
    (i >> 4) & 0xF
}

fn fs(i: u32) -> u32 {
    (i >> 8) & 0xF
}

fn fr(i: u32) -> u32 {
    (i >> 12) & 0xF
}

fn imm8(i: u32) -> u32 {
    (i >> 16) & 0xFF
}

fn sext8(v: u32) -> i32 {
    v as u8 as i8 as i32
}

/// movi imm12 = sext12(s<<8 | imm8) — s is immediate bits, not a register.
fn movi_imm(w: u32) -> i32 {
    let v = (fs(w) << 8 | imm8(w)) as i32;
    if v >= 0x800 { v - 0x1000 } else { v }
}

/// movi.n imm7 = ((t&7)<<4) | r; values ≥ 96 wrap to negative.
fn movi_n_imm(n: u32) -> i32 {
    let v = ((ft(n) & 7) << 4 | fr(n)) as i32;
    if v >= 96 { v - 128 } else { v }
}

/// addi.n imm = t, except t==0 encodes −1 (0 is not encodable).
fn addi_n_imm(n: u32) -> i32 {
    if ft(n) == 0 { -1 } else { ft(n) as i32 }
}

/// Instruction length from byte0's low nibble: 0x0..0x7 ⇒ 3 bytes,
/// 0x8..0xD ⇒ 2; 0xE/0xF are not instructions on esp32s3.
pub fn insn_len(b0: u8) -> Option<usize> {
    match b0 & 0xF {
        0x0..=0x7 => Some(3),
        0x8..=0xD => Some(2),
        _ => None,
    }
}

// ---- narrow/widen pair tables ----
// elf32-xtensa.c `narrowable[]` (~4347) / `widenable[]` (~4360).
// Operand correspondence is semantic value equality through the
// re-encode; `wide`/`narrow` are the pair identity (kept even in loose
// mode), `ops` the value checks (dropped when the slot is relocated).

struct Pair {
    wide: fn(u32) -> bool,
    narrow: fn(u32) -> bool,
    ops: fn(u32, u32) -> bool,
    /// beqz/bnez widen but never narrow ("may require re-expand").
    widen_only: bool,
}

const PAIRS: &[Pair] = &[
    // add ↔ add.n (mask must cover op1 bits 16-19 — 0xF0000F is wrong)
    Pair {
        wide: |w| w & 0xFF000F == 0x800000,
        narrow: |n| op0(n) == 0xA,
        ops: |w, n| fr(w) == fr(n) && fs(w) == fs(n) && ft(w) == ft(n),
        widen_only: false,
    },
    // addi ↔ addi.n: wide dest is t, narrow dest is r
    Pair {
        wide: |w| w & 0x00F00F == 0x00C002,
        narrow: |n| op0(n) == 0xB,
        ops: |w, n| ft(w) == fr(n) && fs(w) == fs(n) && sext8(imm8(w)) == addi_n_imm(n),
        widen_only: false,
    },
    // addmi ↔ addi.n (imm × 256; in ld's table even though the value
    // ranges can never actually meet)
    Pair {
        wide: |w| w & 0x00F00F == 0x00D002,
        narrow: |n| op0(n) == 0xB,
        ops: |w, n| ft(w) == fr(n) && fs(w) == fs(n) && sext8(imm8(w)) * 256 == addi_n_imm(n),
        widen_only: false,
    },
    // l32i ↔ l32i.n: offset imm8×4 vs r×4
    Pair {
        wide: |w| w & 0x00F00F == 0x002002,
        narrow: |n| op0(n) == 0x8,
        ops: |w, n| ft(w) == ft(n) && fs(w) == fs(n) && imm8(w) == fr(n),
        widen_only: false,
    },
    // s32i ↔ s32i.n
    Pair {
        wide: |w| w & 0x00F00F == 0x006002,
        narrow: |n| op0(n) == 0x9,
        ops: |w, n| ft(w) == ft(n) && fs(w) == fs(n) && imm8(w) == fr(n),
        widen_only: false,
    },
    // movi ↔ movi.n: wide dest is t, narrow dest is s
    Pair {
        wide: |w| w & 0x00F00F == 0x00A002,
        narrow: |n| op0(n) == 0xC && ft(n) & 0x8 == 0,
        ops: |w, n| ft(w) == fs(n) && movi_imm(w) == movi_n_imm(n),
        widen_only: false,
    },
    // ret ↔ ret.n / retw ↔ retw.n
    Pair {
        wide: |w| w == 0x000080,
        narrow: |n| n == 0xF00D,
        ops: |_, _| true,
        widen_only: false,
    },
    Pair {
        wide: |w| w == 0x000090,
        narrow: |n| n == 0xF01D,
        ops: |_, _| true,
        widen_only: false,
    },
    // or ↔ mov.n: identity requires equal sources on the wide side
    Pair {
        wide: |w| w & 0xFF000F == 0x200000 && fs(w) == ft(w),
        narrow: |n| op0(n) == 0xD && fr(n) == 0,
        ops: |w, n| fr(w) == ft(n) && fs(w) == fs(n),
        widen_only: false,
    },
    // beqz.n → beqz / bnez.n → bnez: imm is pc-relative (free), s pinned
    Pair {
        wide: |w| w & 0xFF == 0x16,
        narrow: |n| op0(n) == 0xC && ft(n) & 0xC == 0x8,
        ops: |w, n| fs(w) == fs(n),
        widen_only: true,
    },
    Pair {
        wide: |w| w & 0xFF == 0x56,
        narrow: |n| op0(n) == 0xC && ft(n) & 0xC == 0xC,
        ops: |w, n| fs(w) == fs(n),
        widen_only: true,
    },
];

/// ta_narrow_insn: may `wide` have been re-encoded as `narrow`?
pub fn narrow_pair_ok(wide: &[u8], narrow: &[u8], loose: bool) -> bool {
    let (w, n) = (insn24(wide), insn16(narrow));
    PAIRS
        .iter()
        .any(|p| !p.widen_only && (p.wide)(w) && (p.narrow)(n) && (loose || (p.ops)(w, n)))
}

/// ta_widen_insn: may `narrow` have been re-encoded as `wide`?
pub fn widen_pair_ok(narrow: &[u8], wide: &[u8], loose: bool) -> bool {
    let (w, n) = (insn24(wide), insn16(narrow));
    PAIRS
        .iter()
        .any(|p| (p.wide)(w) && (p.narrow)(n) && (loose || (p.ops)(w, n)))
}

// ---- longcall (R_XTENSA_ASM_SIMPLIFY sites; do_asm_simplify ~4711) ----

pub const NOP3: [u8; 3] = [0xF0, 0x20, 0x00];
pub const NOP2: [u8; 2] = [0x3D, 0xF0];
/// The longcall conversion filler is `or a1,a1,a1` — not the canonical nop.
pub const ORNOP: [u8; 3] = [0x10, 0x11, 0x20];

pub fn is_nop3(b: &[u8]) -> bool {
    b.len() >= 3 && b[..3] == NOP3
}

pub fn is_nop2(b: &[u8]) -> bool {
    b.len() >= 2 && b[..2] == NOP2
}

pub fn is_ornop(b: &[u8]) -> bool {
    b.len() >= 3 && b[..3] == ORNOP
}

/// callx0/4/8/12 (byte0 c0/d0/e0/f0) or jx (a0): (kind, len) where kind
/// 0..3 is the call window and 4 the jump; byte1 high nibble and byte2
/// must be zero (s = byte1 low nibble is the target register).
pub fn callx_kind(b: &[u8]) -> Option<(u32, usize)> {
    if b.len() < 3 || b[1] & 0xF0 != 0 || b[2] != 0 {
        return None;
    }
    match b[0] {
        0xC0 => Some((0, 3)),
        0xD0 => Some((1, 3)),
        0xE0 => Some((2, 3)),
        0xF0 => Some((3, 3)),
        0xA0 => Some((4, 3)),
        _ => None,
    }
}

/// call0/4/8/12 (op0=5, window in byte0 bits 4-5) or j (op0=6, n=0):
/// same kind encoding as [`callx_kind`].
pub fn call_kind(b: &[u8]) -> Option<u32> {
    match b[0] & 0xF {
        0x5 => Some(((b[0] >> 4) & 3) as u32),
        0x6 if (b[0] >> 4) & 3 == 0 => Some(4),
        _ => None,
    }
}

/// `l32r aN; callx aN` (adjacent — gas emits the pair as a unit and
/// ld's get_expanded_call_opcode requires adjacency) against either
/// `callN` (remove form) or `or a1,a1,a1; callN` (convert form).
/// Returns (input advance, output advance, converted).
pub fn longcall_match(input: &[u8], output: &[u8]) -> Option<(usize, usize, bool)> {
    if input.len() < 6 || input[0] & 0xF != 1 {
        return None; // not l32r (op0=1)
    }
    let (kind, _) = callx_kind(&input[3..])?;
    if input[3 + 1] & 0xF != input[0] >> 4 {
        return None; // callx target register != l32r destination
    }
    if output.len() >= 3 && call_kind(output) == Some(kind) {
        return Some((6, 3, false));
    }
    if output.len() >= 6 && is_ornop(output) && call_kind(&output[3..]) == Some(kind) {
        return Some((6, 6, true));
    }
    None
}

/// Bit-granular pc-relative free masks for the same-length retarget
/// compare (docs/16 §3). Full-byte masks would let `call8` "match" `j`
/// or a register change slip through.
pub fn free_bits(insn: &[u8]) -> [u8; 3] {
    match insn[0] & 0xF {
        0x1 => [0x00, 0xFF, 0xFF],               // l32r imm16
        0x5 => [0xC0, 0xFF, 0xFF],               // call: offset low bits in byte0
        0x6 => match (insn[0] >> 4) & 3 {
            0 => [0xC0, 0xFF, 0xFF],             // j
            1 => [0x00, 0xF0, 0xFF],             // BRI12: s pinned in byte1
            _ => [0x00, 0x00, 0xFF],             // BRI8 / loop family
        },
        0x7 => [0x00, 0x00, 0xFF],               // two-reg branches
        0xC if insn[0] & 0x80 != 0 => [0x30, 0xF0, 0x00], // beqz.n/bnez.n
        _ => [0x00, 0x00, 0x00],
    }
}

/// The engine's ISA hook, implemented by the free functions above.
pub struct Xtensa;

impl Target for Xtensa {
    fn insn_len(&self, b0: u8) -> Option<usize> {
        insn_len(b0)
    }

    fn free_bits(&self, insn: &[u8]) -> [u8; 3] {
        free_bits(insn)
    }

    fn narrow_ok(&self, wide: &[u8], narrow: &[u8], loose: bool) -> bool {
        narrow_pair_ok(wide, narrow, loose)
    }

    fn widen_ok(&self, narrow: &[u8], wide: &[u8], loose: bool) -> bool {
        widen_pair_ok(narrow, wide, loose)
    }

    fn longcall(&self, input: &[u8], output: &[u8]) -> Option<(usize, usize, bool)> {
        longcall_match(input, output)
    }

    fn nop_len(&self, b: &[u8]) -> Option<usize> {
        if is_nop3(b) {
            Some(3)
        } else if is_nop2(b) {
            Some(2)
        } else {
            None
        }
    }
}

// ---- input-side extraction (docs/16 §4) ----

pub const PROP_LITERAL: u32 = 0x1;
pub const PROP_INSN: u32 = 0x2;
pub const PROP_UNREACHABLE: u32 = 0x8;
pub const PROP_ALIGN: u32 = 0x800;

/// Build the walk's input view of `sec`: bytes, reloc masks, `.xt.prop`
/// regions, flex points, and value-known literal words resolved against
/// the linked image's unique-address symbols.
pub fn extract_input(
    obj: &object::File,
    sec: &object::Section,
    out_syms: &HashMap<String, u64>,
) -> Result<InputSection, String> {
    use object::{ObjectSection, ObjectSymbol, RelocationTarget};

    let sec_name = sec.name().map_err(|e| e.to_string())?;
    let bytes = sec.data().map_err(|e| e.to_string())?.to_vec();

    let mut mask = vec![false; bytes.len()];
    for (off, rel) in sec.relocations() {
        let off = off as usize;
        let n = match rel.size() {
            // SLOT*_OP / ASM_EXPAND report size 0: they cover the
            // instruction slot at that offset (2 or 3 bytes)
            0 => bytes.get(off).and_then(|&b| insn_len(b)).unwrap_or(3),
            bits => bits as usize / 8,
        };
        for m in mask.iter_mut().skip(off).take(n) {
            *m = true;
        }
    }

    let mut regions: Vec<(std::ops::Range<usize>, RegionKind)> = Vec::new();
    let mut flex_points: HashSet<usize> = HashSet::new();
    if sec_name.contains(".literal") {
        // literal sections have no prop entries of their own
        regions.push((0..bytes.len(), RegionKind::Literal));
    } else {
        // .xt.prop: 12-byte (address, size, flags) records; the address
        // field's reloc names the described section via its section
        // symbol — match by physical index, names are not unique
        for prop in object::Object::sections(obj)
            .filter(|s| s.name().is_ok_and(|n| n.starts_with(".xt.prop")))
        {
            let Ok(data) = prop.data() else { continue };
            for (roff, rel) in prop.relocations() {
                let RelocationTarget::Symbol(si) = rel.target() else { continue };
                let Ok(sym) = object::Object::symbol_by_index(obj, si) else { continue };
                if sym.section_index() != Some(sec.index()) {
                    continue;
                }
                let e = roff as usize; // record start == address field
                if e + 12 > data.len() {
                    continue;
                }
                let word =
                    |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
                // gas stores the in-section offset in the FIELD bytes
                // with a zero RELA addend; other emitters use the
                // addend with a zero field — read field + addend
                let start = word(e).wrapping_add(rel.addend() as u32) as usize;
                let size = word(e + 4) as usize;
                let flags = word(e + 8);
                let mut end = start + size;
                if flags & PROP_UNREACHABLE != 0 {
                    // every UNREACHABLE start is a ta_fill site, even
                    // at size 0 (EBB-end pad zeros)
                    flex_points.insert(start);
                    // xtensa_compute_fill_extra_space: the deletable
                    // range extends to the entry's ALIGN boundary
                    if flags & PROP_ALIGN != 0 {
                        let align = 1usize << ((flags >> 12) & 0x1F);
                        end = end.div_ceil(align) * align;
                    }
                }
                let kind = if flags & PROP_LITERAL != 0 {
                    RegionKind::Literal
                } else if flags & PROP_UNREACHABLE != 0 {
                    RegionKind::Unreachable
                } else if flags & PROP_INSN == 0 {
                    RegionKind::Data // jump tables in gcc text
                } else {
                    continue;
                };
                if end > start {
                    regions.push((start..end.min(bytes.len()), kind));
                }
            }
        }
        regions.sort_by_key(|(r, _)| (r.start, r.end));
        regions.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    }

    // literal words with knowable linked values: R_XTENSA_32 against a
    // named symbol with a unique address in the linked image
    let mut lit_expect = HashMap::new();
    for (off, rel) in sec.relocations() {
        let off = off as usize;
        if rel.size() != 32 {
            continue;
        }
        let in_literal = regions
            .iter()
            .any(|(r, k)| *k == RegionKind::Literal && off >= r.start && off + 4 <= r.end);
        if !in_literal {
            continue;
        }
        let RelocationTarget::Symbol(si) = rel.target() else { continue };
        let Ok(sym) = object::Object::symbol_by_index(obj, si) else { continue };
        if sym.kind() == object::SymbolKind::Section {
            continue; // section+offset target: not name-recoverable
        }
        let Ok(name) = sym.name() else { continue };
        if let Some(&addr) = out_syms.get(name) {
            lit_expect.insert(off, addr.wrapping_add(rel.addend() as u64) as u32);
        }
    }

    Ok(InputSection { bytes, mask, regions, flex_points, lit_expect })
}

// Ground-truth bytes assembled with xtensa-esp32s3-elf-as
// (esp-15.2.0_20250920) and read back with readelf -x; ported verbatim
// from the v1 prototype per docs/16 §3. These catch every field-layout
// mistake made along the way.
#[cfg(test)]
mod tests {
    use super::*;

    // wide forms
    const ADD: [u8; 3] = [0x70, 0x35, 0x80]; // add a3,a5,a7
    const ADDI_42: [u8; 3] = [0x32, 0xc5, 0x2a]; // addi a3,a5,42
    const ADDI_M3: [u8; 3] = [0x32, 0xc5, 0xfd]; // addi a3,a5,-3
    const ADDMI: [u8; 3] = [0x32, 0xd5, 0x03]; // addmi a3,a5,0x300
    const L32I: [u8; 3] = [0x32, 0x25, 0x07]; // l32i a3,a5,28
    const MOVI_95: [u8; 3] = [0x32, 0xa0, 0x5f]; // movi a3,95
    const MOVI_M32: [u8; 3] = [0x32, 0xaf, 0xe0]; // movi a3,-32
    const RET: [u8; 3] = [0x80, 0x00, 0x00];
    const RETW: [u8; 3] = [0x90, 0x00, 0x00];
    const S32I: [u8; 3] = [0x32, 0x65, 0x07]; // s32i a3,a5,28
    const OR_MOV: [u8; 3] = [0x50, 0x35, 0x20]; // or a3,a5,a5
    const BEQZ: [u8; 3] = [0x16, 0xe5, 0x02]; // beqz a5,+
    const BNEZ: [u8; 3] = [0x56, 0xb5, 0x02]; // bnez a5,+
    // narrow forms
    const ADD_N: [u8; 2] = [0x7a, 0x35]; // add.n a3,a5,a7
    const ADDI_N_12: [u8; 2] = [0xcb, 0x35]; // addi.n a3,a5,12
    const ADDI_N_M1: [u8; 2] = [0x0b, 0x35]; // addi.n a3,a5,-1
    const L32I_N: [u8; 2] = [0x38, 0x75]; // l32i.n a3,a5,28
    const MOVI_N_95: [u8; 2] = [0x5c, 0xf3]; // movi.n a3,95
    const MOVI_N_M32: [u8; 2] = [0x6c, 0x03]; // movi.n a3,-32
    const RET_N: [u8; 2] = [0x0d, 0xf0];
    const RETW_N: [u8; 2] = [0x1d, 0xf0];
    const S32I_N: [u8; 2] = [0x39, 0x75]; // s32i.n a3,a5,28
    const MOV_N: [u8; 2] = [0x3d, 0x05]; // mov.n a3,a5
    const BEQZ_N: [u8; 2] = [0x9c, 0x45]; // beqz.n a5,+
    const BNEZ_N: [u8; 2] = [0xdc, 0x25]; // bnez.n a5,+
    // longcall pieces
    const L32R: [u8; 3] = [0x31, 0xee, 0xff]; // l32r a3,<lit>
    const CALLX8: [u8; 3] = [0xe0, 0x03, 0x00]; // callx8 a3
    const CALL8: [u8; 3] = [0x65, 0xfb, 0xff]; // call8 <wide>
    const J: [u8; 3] = [0xc6, 0xeb, 0xff]; // j <wide>
    const JX: [u8; 3] = [0xa0, 0x03, 0x00]; // jx a3
    const ORNOP_T: [u8; 3] = [0x10, 0x11, 0x20]; // or a1,a1,a1
    const NOP: [u8; 3] = [0xf0, 0x20, 0x00];
    const NOP_N: [u8; 2] = [0x3d, 0xf0];

    #[test]
    fn narrow_pairs_accept() {
        // addi a3,a5,12 (synthesized: imm8=0x0c)
        let addi_12: [u8; 3] = [0x32, 0xc5, 0x0c];
        let addi_m1: [u8; 3] = [0x32, 0xc5, 0xff];
        assert!(narrow_pair_ok(&ADD, &ADD_N, false));
        assert!(narrow_pair_ok(&addi_12, &ADDI_N_12, false));
        assert!(narrow_pair_ok(&addi_m1, &ADDI_N_M1, false));
        assert!(narrow_pair_ok(&L32I, &L32I_N, false));
        assert!(narrow_pair_ok(&MOVI_95, &MOVI_N_95, false));
        assert!(narrow_pair_ok(&MOVI_M32, &MOVI_N_M32, false));
        assert!(narrow_pair_ok(&RET, &RET_N, false));
        assert!(narrow_pair_ok(&RETW, &RETW_N, false));
        assert!(narrow_pair_ok(&S32I, &S32I_N, false));
        assert!(narrow_pair_ok(&OR_MOV, &MOV_N, false));
    }

    #[test]
    fn narrow_pairs_reject() {
        // operand value mismatch
        assert!(!narrow_pair_ok(&ADDI_42, &ADDI_N_12, false));
        assert!(!narrow_pair_ok(&ADDI_M3, &ADDI_N_M1, false));
        assert!(!narrow_pair_ok(&ADDMI, &ADDI_N_12, false)); // 768 != 12
        assert!(!narrow_pair_ok(&MOVI_95, &MOVI_N_M32, false));
        // register mismatch: l32i a3,a5,28 vs s32i.n a3,a5,28
        assert!(!narrow_pair_ok(&L32I, &S32I_N, false));
        // or with distinct sources is NOT mov
        let or_356: [u8; 3] = [0x60, 0x35, 0x20]; // or a3,a5,a6
        assert!(!narrow_pair_ok(&or_356, &MOV_N, false));
        // branches are NOT narrowable (linker table excludes them)
        assert!(!narrow_pair_ok(&BEQZ, &BEQZ_N, false));
        assert!(!narrow_pair_ok(&BNEZ, &BNEZ_N, false));
        // loose mode still requires the pair identity
        assert!(!narrow_pair_ok(&RET, &MOV_N, true));
        assert!(narrow_pair_ok(&ADDI_42, &ADDI_N_12, true)); // imm free when masked
    }

    #[test]
    fn widen_pairs() {
        assert!(widen_pair_ok(&ADD_N, &ADD, false));
        assert!(widen_pair_ok(&RET_N, &RET, false));
        assert!(widen_pair_ok(&MOV_N, &OR_MOV, false));
        // branches widen (imm is pc-relative, register must hold)
        assert!(widen_pair_ok(&BEQZ_N, &BEQZ, false));
        assert!(widen_pair_ok(&BNEZ_N, &BNEZ, false));
        assert!(!widen_pair_ok(&BEQZ_N, &BNEZ, false));
        let beqz_a4: [u8; 3] = [0x16, 0xe4, 0x02];
        assert!(!widen_pair_ok(&BEQZ_N, &beqz_a4, false)); // reg mismatch
    }

    #[test]
    fn longcall_forms() {
        let mut site = Vec::new();
        site.extend_from_slice(&L32R);
        site.extend_from_slice(&CALLX8);
        // remove form: callx8 -> call8
        assert_eq!(longcall_match(&site, &CALL8), Some((6, 3, false)));
        // convert form: or-nop + call8
        let mut conv = Vec::new();
        conv.extend_from_slice(&ORNOP_T);
        conv.extend_from_slice(&CALL8);
        assert_eq!(longcall_match(&site, &conv), Some((6, 6, true)));
        // window mismatch: callx8 cannot become call4
        let call4: [u8; 3] = [0x55, 0xfb, 0xff];
        assert_eq!(longcall_match(&site, &call4), None);
        // register mismatch: l32r a3 + callx8 a4
        let mut bad = Vec::new();
        bad.extend_from_slice(&L32R);
        bad.extend_from_slice(&[0xe0, 0x04, 0x00]);
        assert_eq!(longcall_match(&bad, &CALL8), None);
        // jx -> j
        let mut jsite = Vec::new();
        jsite.extend_from_slice(&L32R);
        jsite.extend_from_slice(&JX);
        assert_eq!(longcall_match(&jsite, &J), Some((6, 3, false)));
    }

    #[test]
    fn pcrel_free_bits() {
        // call8 retargeted: only offset bits differ
        let call8_other: [u8; 3] = [0xa5, 0x01, 0x00];
        let fb = free_bits(&CALL8);
        for k in 0..3 {
            assert_eq!((CALL8[k] ^ call8_other[k]) & !fb[k], 0);
        }
        // call8 vs j differs in op0/n bits: must NOT be free
        assert_ne!((CALL8[0] ^ J[0]) & !fb[0], 0);
        // beqz imm12 free, s pinned
        let beqz_other: [u8; 3] = [0x16, 0x75, 0x99]; // beqz a5, elsewhere
        let fb = free_bits(&BEQZ);
        for k in 0..3 {
            assert_eq!((BEQZ[k] ^ beqz_other[k]) & !fb[k], 0);
        }
        let beqz_a4: [u8; 3] = [0x16, 0xe4, 0x02];
        assert_ne!((BEQZ[1] ^ beqz_a4[1]) & !fb[1], 0);
    }

    #[test]
    fn misc_decode() {
        assert!(is_nop3(&NOP));
        assert!(is_nop2(&NOP_N));
        assert!(is_ornop(&ORNOP_T));
        assert!(!is_ornop(&NOP));
        assert_eq!(insn_len(L32R[0]), Some(3));
        assert_eq!(insn_len(ADD_N[0]), Some(2));
        assert_eq!(insn_len(0xfe), None);
        assert_eq!(callx_kind(&CALLX8), Some((2, 3)));
        assert_eq!(callx_kind(&JX), Some((4, 3)));
        assert_eq!(call_kind(&CALL8), Some(2));
        assert_eq!(call_kind(&J), Some(4));
        assert_eq!(call_kind(&BEQZ), None); // op0=6 but n=1
    }
}
