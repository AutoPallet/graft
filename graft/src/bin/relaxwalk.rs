//! Isolated prototype of the relaxation reconciliation walk (task #32).
//!
//! Feeds on a real link: the GNU ld -Map names every input section that
//! relaxed ("(size before relaxing)") plus its output (start, size); the
//! input object supplies pre-relaxation bytes + relocs + .xt.prop; the
//! linked ELF supplies post-relaxation bytes. The walk advances a cursor
//! through both byte streams, explaining every byte with the transform
//! alphabet transcribed from bfd/elf32-xtensa.c (espressif binutils-gdb
//! tag esp-2.45.0_20250920 — the toolchain that linked the corpus):
//!
//!   verbatim    same-length insn, bytes equal modulo input reloc fields
//!               and pc-relative immediate bits (ld retargets in place)
//!   longcall    ta_remove_longcall: l32r+callx (adjacent, ASM_SIMPLIFY
//!               site) -> call; ta_convert_longcall: -> "or a1,a1,a1"
//!               nop + call (elf_xtensa_do_asm_simplify)
//!   narrow      ta_narrow_insn: exact `narrowable[]` pair table, operand
//!               values preserved through re-encode
//!   widen       ta_widen_insn: exact `widenable[]` pair table (adds
//!               beqz.n/bnez.n -> beqz/bnez; branch imm is pc-relative)
//!   fill        ta_fill removed<0: ZERO bytes inserted (dup_contents is
//!               calloc'd); removed>=0: bytes deleted. Only at EBB ends =
//!               XTENSA_PROP_UNREACHABLE ranges or section tail.
//!   lit-del     ta_remove_literal: 4-byte word deleted from a literal
//!               range (dead or coalesced into another pool)
//!   lit-add     ta_add_literal: 4-byte word inserted into a literal
//!               range (a moved literal)
//!   data        XTENSA_PROP_DATA / non-INSN prop ranges in text (jump
//!               tables): raw bytes, no insn decode, no transforms
//!
//! Rules NOT in elf32-xtensa.c are kept only as tagged diagnostics
//! (nop fill/unfill) so the census shows whether anything real needs
//! them; they never count as a clean reconcile.
//!
//! Anything unexplained falls to a weighted 0-1-Dijkstra search whose
//! catch-all edges localize replaced-byte runs (Dirty verdict) for
//! pattern mining. Ambiguity detection (DP-intersection over all
//! min-cost parses) is the production safety net and comes after the
//! alphabet is complete; loose rules here are acceptable because an
//! ambiguous byte translation bails at resolve time.
//!
//! Usage:
//!   relaxwalk --map M --elf E [--path-map FROM=TO] [--limit N] [-v] [--filter S]

use std::collections::HashMap;
use std::path::PathBuf;

use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget};

// ---------- map parsing (standalone; relaxed entries only) ----------

#[derive(Debug, Clone)]
struct RelaxedSec {
    in_name: String,
    addr: u64,
    out_size: u64,
    in_size: u64,
    obj: String, // "/path/lib.a(member.o)" or "/path/file.o"
}

fn parse_map(text: &str) -> Vec<RelaxedSec> {
    let mut out = Vec::new();
    let mut pending_name: Option<String> = None;
    let mut last: Option<RelaxedSec> = None;
    for line in text.lines() {
        let t = line.trim_start();
        // " .text.foo" alone on a line (long names wrap)
        if line.starts_with(" .") && !t.contains("0x") {
            pending_name = Some(t.to_string());
            continue;
        }
        // "(size before relaxing)" annotates the previous addr/size line
        if t.ends_with("(size before relaxing)") {
            if let (Some(mut sec), Some(sz)) = (last.take(), t.split_whitespace().next()) {
                if let Some(sz) = parse_hex(sz) {
                    sec.in_size = sz;
                    out.push(sec);
                }
            }
            continue;
        }
        // addr/size/obj line, either with inline name or following a bare-name line
        let mut words = t.split_whitespace();
        let (name, a) = if line.starts_with(" .") {
            (words.next().map(str::to_string), words.next())
        } else {
            (pending_name.take(), words.next())
        };
        let (Some(name), Some(a), Some(s), Some(obj)) = (name, a, words.next(), words.next())
        else {
            last = None;
            continue;
        };
        if let (Some(addr), Some(size)) = (parse_hex(a), parse_hex(s)) {
            last = Some(RelaxedSec { in_name: name, addr, out_size: size, in_size: 0, obj: obj.to_string() });
        } else {
            last = None;
        }
    }
    out
}

fn parse_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

// ---------- input-side extraction ----------

struct InputSec {
    bytes: Vec<u8>,
    /// byte positions covered by relocation fields (value may differ freely)
    mask: Vec<bool>,
    /// XTENSA_PROP_LITERAL ranges (whole .literal.* sections, or prop
    /// entries inside text for gcc embedded literals)
    literal_ranges: Vec<(usize, usize)>,
    /// XTENSA_PROP_UNREACHABLE ranges: ta_fill territory (bytes deleted
    /// or zeros inserted at EBB ends)
    unreachable_ranges: Vec<(usize, usize)>,
    /// prop ranges with neither INSN nor LITERAL nor UNREACHABLE set:
    /// data-in-text (jump tables) -- raw bytes, never transformed
    data_ranges: Vec<(usize, usize)>,
    /// literal words whose post-link value is knowable: R_XTENSA_32
    /// against a symbol with a unique address in the linked ELF. Keyed
    /// by word offset; a masked word with an expected value matches by
    /// VALUE, which makes dead-literal removal deterministic instead of
    /// positional guesswork (a dead masked word must not eat code).
    lit_expect: HashMap<usize, u32>,
    /// starts of ALL unreachable prop entries, including size-0 ones:
    /// ta_fill points where ld may insert zero bytes (removed_bytes =
    /// extra_space - br goes negative when the EBB's removals don't hit
    /// the alignment and ld pads instead of rippling)
    flex_points: std::collections::HashSet<usize>,
}

/// expected output value for a literal word: match by value when known,
/// by reloc-mask otherwise, by raw bytes when unrelocated
fn lit_word_matches(inp: &InputSec, i: usize, out_w: &[u8]) -> bool {
    if let Some(&want) = inp.lit_expect.get(&i) {
        return u32::from_le_bytes(out_w.try_into().unwrap()) == want;
    }
    let masked = inp.mask[i..i + 4].iter().any(|&m| m);
    masked || inp.bytes[i..i + 4] == out_w[..4]
}

#[derive(Clone, Copy, PartialEq)]
enum Region {
    Code,
    Literal(usize),
    Unreach(usize),
    Data(usize),
}

impl InputSec {
    fn region_at(&self, i: usize) -> Region {
        if let Some(&(_, e)) = self.literal_ranges.iter().find(|&&(s, e)| i >= s && i < e) {
            return Region::Literal(e);
        }
        if let Some(&(_, e)) = self.unreachable_ranges.iter().find(|&&(s, e)| i >= s && i < e) {
            return Region::Unreach(e);
        }
        if let Some(&(_, e)) = self.data_ranges.iter().find(|&&(s, e)| i >= s && i < e) {
            return Region::Data(e);
        }
        Region::Code
    }
}

// .xt.prop flags (include/elf/xtensa.h)
const PROP_LITERAL: u32 = 0x1;
const PROP_INSN: u32 = 0x2;
const PROP_UNREACHABLE: u32 = 0x8;
const PROP_ALIGN: u32 = 0x800; // alignment pow2 in bits 12-16

fn load_input(
    obj_spec: &str,
    sec_name: &str,
    want_size: u64,
    out_syms: &HashMap<String, u64>,
    v: bool,
) -> Result<InputSec, String> {
    let (path, member) = match obj_spec.split_once('(') {
        Some((p, m)) => (p.to_string(), Some(m.trim_end_matches(')').to_string())),
        None => (obj_spec.to_string(), None),
    };
    let file_data = std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
    // archives can hold several members with the SAME name (esp-idf links
    // generic + per-chip bignum.c.obj into libmbedcrypto.a); the map names
    // members by string only, so collect every name match and let the
    // section-level size disambiguation below pick the right one.
    // (Production graft knows exact member offsets from its own scan.)
    let member_datas: Vec<Vec<u8>> = match &member {
        Some(m) => {
            let ar = object::read::archive::ArchiveFile::parse(&*file_data)
                .map_err(|e| format!("archive {path}: {e}"))?;
            let mut found = Vec::new();
            for mem in ar.members() {
                let mem = mem.map_err(|e| e.to_string())?;
                if String::from_utf8_lossy(mem.name()) == *m {
                    found.push(mem.data(&*file_data).map_err(|e| e.to_string())?.to_vec());
                }
            }
            if found.is_empty() {
                return Err(format!("member {m} not in {path}"));
            }
            found
        }
        None => vec![file_data.clone()],
    };
    let objs: Vec<object::File> = member_datas
        .iter()
        .map(|d| object::File::parse(&**d).map_err(|e| format!("parse: {e}")))
        .collect::<Result<_, _>>()?;

    // same-named sections are legal (within an object AND across
    // same-named members); disambiguate by size
    let mut candidates: Vec<(usize, object::read::SectionIndex)> = Vec::new();
    for (oi, obj) in objs.iter().enumerate() {
        for s in obj.sections() {
            if s.name().map(|n| n == sec_name).unwrap_or(false) {
                candidates.push((oi, s.index()));
            }
        }
    }
    if candidates.len() > 1 {
        candidates.retain(|&(oi, si)| {
            objs[oi].section_by_index(si).map(|s| s.size() == want_size).unwrap_or(false)
        });
    }
    if candidates.len() != 1 {
        return Err(format!("ambiguous-or-missing section ({} candidates)", candidates.len()));
    }
    let obj = &objs[candidates[0].0];
    let sec = &obj.section_by_index(candidates[0].1).map_err(|e| e.to_string())?;
    // only instruction streams walk; non-exec "relaxed" sections are
    // merge-string folding (different mechanism, v7 territory)
    let is_exec = matches!(sec.kind(), object::SectionKind::Text);
    if !is_exec && !sec_name.contains(".literal") {
        return Err("merge-fold (non-exec)".into());
    }
    let bytes = sec.data().map_err(|e| e.to_string())?.to_vec();
    if bytes.len() as u64 != want_size {
        return Err(format!("input size {} != map before-relax {}", bytes.len(), want_size));
    }

    let mut mask = vec![false; bytes.len()];
    for (off, rel) in sec.relocations() {
        let n = match rel.size() {
            // xtensa SLOT*_OP / ASM_EXPAND relocs report size 0: they
            // cover the insn slot at that offset (2 or 3 bytes)
            0 => bytes
                .get(off as usize)
                .and_then(|&b| insn_len(b))
                .unwrap_or(3),
            b => (b as usize) / 8,
        };
        for i in 0..n {
            if let Some(m) = mask.get_mut(off as usize + i) {
                *m = true;
            }
        }
    }

    let mut literal_ranges = Vec::new();
    let mut unreachable_ranges = Vec::new();
    let mut data_ranges = Vec::new();
    let mut flex_points = std::collections::HashSet::new();
    if sec_name.contains(".literal") {
        literal_ranges.push((0, bytes.len()));
    } else {
        // .xt.prop entries are 12-byte records (addr, size, flags); the
        // addr field carries a reloc against the described section
        for prop in obj.sections().filter(|s| s.name().map(|n| n.starts_with(".xt.prop")).unwrap_or(false)) {
            let data = match prop.data() {
                Ok(d) => d,
                Err(_) => continue,
            };
            for (roff, rel) in prop.relocations() {
                let RelocationTarget::Symbol(si) = rel.target() else { continue };
                let Ok(sym) = obj.symbol_by_index(si) else { continue };
                if sym.section_index() != Some(sec.index()) {
                    continue;
                }
                let e = roff as usize; // entry start == addr field offset
                if e + 12 > data.len() {
                    continue;
                }
                let rd = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
                // gas stores the in-section offset in the FIELD bytes with a
                // zero RELA addend (legacy REL-style); other emitters use the
                // addend with a zero field. Sum covers both.
                let start = rd(e).wrapping_add(rel.addend() as u32);
                let (size, flags) = (rd(e + 4), rd(e + 8));
                let mut end = start + size;
                if flags & PROP_UNREACHABLE != 0 {
                    // every unreachable start is a ta_fill site: zeros can
                    // be inserted here even when the entry is empty
                    flex_points.insert(start as usize);
                    // mirror xtensa_compute_fill_extra_space: the deletable
                    // region extends to the entry's ALIGN boundary (gas
                    // emits size-0 align-4 entries for inter-function
                    // padding)
                    if flags & PROP_ALIGN != 0 {
                        let align = 1u32 << ((flags >> 12) & 0x1F);
                        end = end.wrapping_add(align - 1) & !(align - 1);
                    }
                }
                if end == start {
                    continue;
                }
                let range = (start as usize, end as usize);
                if flags & PROP_LITERAL != 0 {
                    literal_ranges.push(range);
                } else if flags & PROP_UNREACHABLE != 0 {
                    unreachable_ranges.push(range);
                } else if flags & PROP_INSN == 0 {
                    // neither insn nor literal nor unreachable: raw data
                    data_ranges.push(range);
                }
            }
        }
        for r in [&mut literal_ranges, &mut unreachable_ranges, &mut data_ranges] {
            r.sort();
            r.dedup();
        }
    }
    // resolve literal-word values: R_XTENSA_32 against a named symbol
    // with a unique address in the linked image
    let mut lit_expect = HashMap::new();
    for (off, rel) in sec.relocations() {
        let off = off as usize;
        if rel.size() != 32 || !literal_ranges.iter().any(|&(s, e)| off >= s && off + 4 <= e) {
            continue;
        }
        let RelocationTarget::Symbol(si) = rel.target() else { continue };
        let Ok(sym) = obj.symbol_by_index(si) else { continue };
        if sym.kind() == object::SymbolKind::Section {
            continue; // local section+offset target: address not name-recoverable
        }
        let Ok(name) = sym.name() else { continue };
        if let Some(&addr) = out_syms.get(name) {
            lit_expect.insert(off, addr.wrapping_add(rel.addend() as u64) as u32);
        }
    }
    if v {
        eprintln!(
            "  input {} bytes, {} literal / {} unreachable / {} data ranges, {} value-known words",
            bytes.len(),
            literal_ranges.len(),
            unreachable_ranges.len(),
            data_ranges.len(),
            lit_expect.len()
        );
    }
    Ok(InputSec { bytes, mask, literal_ranges, unreachable_ranges, data_ranges, lit_expect, flex_points })
}

// ---------- xtensa decode (LE) ----------
//
// 24-bit insn = b0 | b1<<8 | b2<<16; op0 = insn & 0xF
// fields: t = (>>4)&F, s = (>>8)&F, r = (>>12)&F, imm8 = (>>16)&FF
// 16-bit insn = b0 | b1<<8; same t/s/r field positions.
// Encodings verified against xtensa-esp32s3-elf-as (esp-15.2.0_20250920);
// see the unit tests for the assembled ground-truth bytes.

fn insn_len(b: u8) -> Option<usize> {
    match b & 0x0F {
        0x0..=0x7 => Some(3),
        0x8..=0xD => Some(2),
        _ => None,
    }
}
fn insn24(b: &[u8]) -> u32 {
    b[0] as u32 | (b[1] as u32) << 8 | (b[2] as u32) << 16
}
fn insn16(b: &[u8]) -> u32 {
    b[0] as u32 | (b[1] as u32) << 8
}
fn is_l32r(i: &[u8]) -> bool {
    i.len() >= 3 && i[0] & 0x0F == 0x1
}
/// CALLX0/4/8/12 = byte0 c0/d0/e0/f0, byte1 = 0S, byte2 = 00; JX = a0.
/// Returns the call-window index n (0..3) or 4 for jx, plus source reg.
fn callx_kind(i: &[u8]) -> Option<(u8, u8)> {
    if i.len() < 3 || i[2] != 0x00 || i[1] & 0xF0 != 0 {
        return None;
    }
    let s = i[1] & 0x0F;
    match i[0] {
        0xc0 => Some((0, s)),
        0xd0 => Some((1, s)),
        0xe0 => Some((2, s)),
        0xf0 => Some((3, s)),
        0xa0 => Some((4, s)), // jx (kept though elf32-xtensa only swaps callx)
        _ => None,
    }
}
/// CALL0/4/8/12 = op0 5, n in byte0 bits 4-5; J = op0 6, n = 0.
/// Returns the window index (0..3) or 4 for j.
fn call_kind(o: &[u8]) -> Option<u8> {
    if o.len() < 3 {
        return None;
    }
    match o[0] & 0x0F {
        0x5 => Some((o[0] >> 4) & 0x3),
        0x6 if (o[0] >> 4) & 0x3 == 0 => Some(4),
        _ => None,
    }
}
/// The NOP that elf_xtensa_do_asm_simplify writes for ta_convert_longcall
/// is "or a1, a1, a1" (insn 0x201110), NOT the canonical nop.
fn is_ornop(o: &[u8]) -> bool {
    o.len() >= 3 && o[0] == 0x10 && o[1] == 0x11 && o[2] == 0x20
}
fn is_nop3(i: &[u8]) -> bool {
    i.len() >= 3 && i[0] == 0xf0 && i[1] == 0x20 && i[2] == 0x00
}
fn is_nop2(i: &[u8]) -> bool {
    i.len() >= 2 && i[0] == 0x3d && i[1] == 0xf0
}

/// Per-byte bit masks of fields ld may rewrite in place for a
/// same-length insn: pc-relative immediates (branches, call/j, l32r).
/// Bits set = free to differ. Conservative and bit-granular: opcode and
/// register fields stay pinned.
fn free_bits(i: &[u8]) -> [u8; 3] {
    match i[0] & 0x0F {
        0x1 => [0x00, 0xFF, 0xFF],        // l32r: imm16 (literal moved/deduped)
        0x5 => [0xC0, 0xFF, 0xFF],        // call: offset18 incl. byte0 bits 6-7
        0x6 => match (i[0] >> 4) & 0x3 {
            0 => [0xC0, 0xFF, 0xFF],      // j: offset18
            1 => [0x00, 0xF0, 0xFF],      // BRI12 beqz/bnez/bgez/bltz: imm12
            _ => [0x00, 0x00, 0xFF],      // BRI8/loop/entry: imm8 in byte2
        },
        0x7 => [0x00, 0x00, 0xFF],        // B-format two-reg branches: imm8
        _ => [0x00, 0x00, 0x00],
    }
}
/// beqz.n/bnez.n imm6 free bits for the 2-byte form: imm6 = ((t&3)<<4)|r,
/// i.e. byte0 bits 4-5 and byte1 bits 4-7.
fn free_bits_2(i: &[u8]) -> [u8; 2] {
    if i[0] & 0x0F == 0xC && i[0] & 0x80 != 0 {
        // t bit3 (byte0 bit 7) set => beqz.n/bnez.n
        [0x30, 0xF0]
    } else {
        [0x00, 0x00]
    }
}

// --- exact narrowable/widenable pair tables (elf32-xtensa.c:4347,4360) ---

/// Canonical identity of a wide (24-bit) insn that appears in the pair
/// tables, with semantic operand values.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Wide {
    Add { r: u8, s: u8, t: u8 },
    Addi { t: u8, s: u8, imm: i32 },
    Addmi { t: u8, s: u8, imm: i32 },
    L32i { t: u8, s: u8, off: u32 },
    Movi { t: u8, imm: i32 },
    Ret,
    Retw,
    S32i { t: u8, s: u8, off: u32 },
    Or { r: u8, s: u8, t: u8 },
    Beqz { s: u8 },
    Bnez { s: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Narrow {
    AddN { r: u8, s: u8, t: u8 },
    AddiN { r: u8, s: u8, imm: i32 },
    L32iN { t: u8, s: u8, off: u32 },
    MoviN { s: u8, imm: i32 },
    RetN,
    RetwN,
    S32iN { t: u8, s: u8, off: u32 },
    MovN { t: u8, s: u8 },
    BeqzN { s: u8 },
    BnezN { s: u8 },
}

fn wide_id(b: &[u8]) -> Option<Wide> {
    let insn = insn24(b);
    let t = ((insn >> 4) & 0xF) as u8;
    let s = ((insn >> 8) & 0xF) as u8;
    let r = ((insn >> 12) & 0xF) as u8;
    let imm8 = ((insn >> 16) & 0xFF) as u32;
    if insn == 0x000080 {
        return Some(Wide::Ret);
    }
    if insn == 0x000090 {
        return Some(Wide::Retw);
    }
    match insn & 0xFF000F {
        0x800000 => return Some(Wide::Add { r, s, t }),
        0x200000 => return Some(Wide::Or { r, s, t }),
        _ => {}
    }
    match insn & 0x00F00F {
        0x00C002 => return Some(Wide::Addi { t, s, imm: (imm8 as i8) as i32 }),
        0x00D002 => return Some(Wide::Addmi { t, s, imm: (imm8 as i8) as i32 * 256 }),
        0x002002 => return Some(Wide::L32i { t, s, off: imm8 * 4 }),
        0x006002 => return Some(Wide::S32i { t, s, off: imm8 * 4 }),
        0x00A002 => {
            let imm12 = ((s as u32) << 8 | imm8) as i32;
            let imm = if imm12 >= 2048 { imm12 - 4096 } else { imm12 };
            return Some(Wide::Movi { t, imm });
        }
        _ => {}
    }
    match b[0] {
        0x16 => Some(Wide::Beqz { s }),
        0x56 => Some(Wide::Bnez { s }),
        _ => None,
    }
}

fn narrow_id(b: &[u8]) -> Option<Narrow> {
    let insn = insn16(b);
    let t = ((insn >> 4) & 0xF) as u8;
    let s = ((insn >> 8) & 0xF) as u8;
    let r = ((insn >> 12) & 0xF) as u8;
    match insn & 0xF {
        0x8 => Some(Narrow::L32iN { t, s, off: r as u32 * 4 }),
        0x9 => Some(Narrow::S32iN { t, s, off: r as u32 * 4 }),
        0xA => Some(Narrow::AddN { r, s, t }),
        0xB => Some(Narrow::AddiN { r, s, imm: if t == 0 { -1 } else { t as i32 } }),
        0xC => {
            if t & 0x8 == 0 {
                let imm7 = ((t as i32 & 0x7) << 4) | r as i32;
                let imm = if imm7 >= 96 { imm7 - 128 } else { imm7 };
                Some(Narrow::MoviN { s, imm })
            } else if t & 0x4 == 0 {
                Some(Narrow::BeqzN { s })
            } else {
                Some(Narrow::BnezN { s })
            }
        }
        0xD => match insn {
            0xf00d => Some(Narrow::RetN),
            0xf01d => Some(Narrow::RetwN),
            _ if r == 0 => Some(Narrow::MovN { t, s }),
            _ => None,
        },
        _ => None,
    }
}

/// ta_narrow_insn: `narrowable[]` — NO branches (beqz/bnez excluded from
/// narrowing because they might need to re-expand). Operand values are
/// preserved through the re-encode. `loose` (input slot reloc-masked):
/// only the pair identity is checked, not operand values.
fn narrow_pair_ok(inb: &[u8], outb: &[u8], loose: bool) -> bool {
    let (Some(w), Some(n)) = (wide_id(inb), narrow_id(outb)) else {
        return false;
    };
    match (w, n) {
        (Wide::Add { r, s, t }, Narrow::AddN { r: nr, s: ns, t: nt }) => {
            loose || (r == nr && s == ns && t == nt)
        }
        (Wide::Addi { t, s, imm }, Narrow::AddiN { r, s: ns, imm: ni })
        | (Wide::Addmi { t, s, imm }, Narrow::AddiN { r, s: ns, imm: ni }) => {
            (t == r && s == ns) && (loose || imm == ni)
        }
        (Wide::L32i { t, s, off }, Narrow::L32iN { t: nt, s: ns, off: no }) => {
            (t == nt && s == ns) && (loose || off == no)
        }
        (Wide::S32i { t, s, off }, Narrow::S32iN { t: nt, s: ns, off: no }) => {
            (t == nt && s == ns) && (loose || off == no)
        }
        (Wide::Movi { t, imm }, Narrow::MoviN { s, imm: ni }) => {
            t == s && (loose || imm == ni)
        }
        (Wide::Ret, Narrow::RetN) | (Wide::Retw, Narrow::RetwN) => true,
        // "or" -> mov.n special case only when the two sources are equal
        (Wide::Or { r, s, t }, Narrow::MovN { t: nt, s: ns }) => s == t && r == nt && s == ns,
        _ => false,
    }
}

/// ta_widen_insn: `widenable[]` = narrowable pairs PLUS beqz.n/bnez.n.
/// Branch immediates are pc-relative (target may have moved): reg only.
fn widen_pair_ok(inb: &[u8], outb: &[u8], loose: bool) -> bool {
    if let (Some(n), Some(w)) = (narrow_id(inb), wide_id(outb)) {
        match (n, w) {
            (Narrow::BeqzN { s }, Wide::Beqz { s: ws }) => return loose || s == ws,
            (Narrow::BnezN { s }, Wide::Bnez { s: ws }) => return loose || s == ws,
            _ => {}
        }
    }
    // remaining pairs are the narrowable table in reverse
    narrow_pair_ok(outb, inb, loose)
}

/// Longcall site (R_XTENSA_ASM_SIMPLIFY): input must be the adjacent
/// `l32r aN; callx aN` pair gas emitted for -mlongcalls. Output is
/// either `call` (ta_remove_longcall) or `or a1,a1,a1; call`
/// (ta_convert_longcall). Returns (in_adv, out_adv, converted).
fn longcall_match(inb: &[u8], outb: &[u8]) -> Option<(usize, usize, bool)> {
    if inb.len() < 6 || !is_l32r(inb) {
        return None;
    }
    let l32r_t = (inb[0] >> 4) & 0xF;
    let (kind, callx_s) = callx_kind(&inb[3..])?;
    if l32r_t != callx_s {
        return None;
    }
    // remove form: bare call/j
    if outb.len() >= 3 && call_kind(outb) == Some(kind) {
        return Some((6, 3, false));
    }
    // convert form: or-nop then call/j
    if outb.len() >= 6 && is_ornop(outb) && call_kind(&outb[3..]) == Some(kind) {
        return Some((6, 6, true));
    }
    None
}

// ---------- the walk ----------

#[derive(Default, Debug)]
struct Counts {
    verbatim: usize,
    retarget: usize,
    longcall: usize,
    longcall_convert: usize,
    narrow: usize,
    widen: usize,
    fill_zero: usize,
    unreach_del: usize,
    lit_del_words: usize,
    lit_add_words: usize,
    data_bytes: usize,
    /// equal bytes advanced 1:1 without insn decode. ld's copy loop is
    /// byte-oriented (memmove between action offsets); this covers
    /// verbatim regions that don't parse as instructions, e.g. unmarked
    /// zero padding straddled by the insn decoder
    byte_verbatim: usize,
    /// diagnostics: rules NOT in elf32-xtensa.c (suspect if nonzero)
    nop_fill: usize,
    nop_unfill: usize,
    end_trim: usize,
}

impl Counts {
    fn absorb(&mut self, o: &Counts) {
        self.verbatim += o.verbatim;
        self.retarget += o.retarget;
        self.longcall += o.longcall;
        self.longcall_convert += o.longcall_convert;
        self.narrow += o.narrow;
        self.widen += o.widen;
        self.fill_zero += o.fill_zero;
        self.unreach_del += o.unreach_del;
        self.lit_del_words += o.lit_del_words;
        self.lit_add_words += o.lit_add_words;
        self.data_bytes += o.data_bytes;
        self.byte_verbatim += o.byte_verbatim;
        self.nop_fill += o.nop_fill;
        self.nop_unfill += o.nop_unfill;
        self.end_trim += o.end_trim;
    }
    fn used_diag(&self) -> bool {
        self.nop_fill != 0 || self.nop_unfill != 0
    }
}

enum Verdict {
    Reconciled(Counts, usize /* windows */),
    Refused { in_off: usize, out_off: usize, reason: String },
    /// weighted search succeeded only via catch-all edges: the listed
    /// (in_off, in_len, out_len) runs are "bytes probably replaced"
    Dirty { cost: u32, replaced: Vec<(usize, usize, usize)> },
}

// Dijkstra action codes
const A_VERBATIM: u8 = 0;
const A_RETARGET: u8 = 1;
const A_LONGCALL: u8 = 2;
const A_NARROW: u8 = 3;
const A_WIDEN: u8 = 4;
const A_FILL_ZERO: u8 = 5;
const A_END_TRIM: u8 = 6;
const A_LIT_DEL: u8 = 7;
const A_NOP_FILL: u8 = 8;
const A_NOP_UNFILL: u8 = 9;
const A_REPLACE: u8 = 10;
const A_SKIP_IN: u8 = 11;
const A_SKIP_OUT: u8 = 12;
const A_LONGCALL_CONV: u8 = 13;
const A_LIT_ADD: u8 = 14;
const A_DATA: u8 = 15;
const A_UNREACH_DEL: u8 = 16;
const A_BYTE_VERBATIM: u8 = 17;

/// Weighted matching search: 0-1-Dijkstra over (i,o) states. Known
/// transforms are cheap; catch-all skip/replace edges expensive; the
/// non-source nop rules sit in between (visible but never preferred
/// over a source-grounded parse). A clean min-cost path == reconcile;
/// a dirty path localizes the unexplained byte runs.
fn walk_dijkstra(inp: &InputSec, out: &[u8]) -> Verdict {
    use std::collections::{BinaryHeap, HashMap};
    const C_KNOWN: u32 = 1;
    const C_NOP_DIAG: u32 = 6;
    const C_REPLACE: u32 = 12;
    const C_SKIP: u32 = 16;
    let inb = &inp.bytes;
    let (n, m) = (inb.len(), out.len());
    let key = |i: usize, o: usize| (i as u64) << 32 | o as u64;
    let mut dist: HashMap<u64, u32> = HashMap::new();
    let mut prev: HashMap<u64, (usize, usize, u8)> = HashMap::new();
    let mut heap = BinaryHeap::new();
    heap.push((std::cmp::Reverse(0u32), 0usize, 0usize));
    dist.insert(key(0, 0), 0);
    let mut explored = 0usize;
    while let Some((std::cmp::Reverse(d), i, o)) = heap.pop() {
        if dist.get(&key(i, o)).copied().unwrap_or(u32::MAX) < d {
            continue;
        }
        explored += 1;
        if explored > 3_000_000 {
            return Verdict::Refused { in_off: i, out_off: o, reason: "search overflow".into() };
        }
        if i == n && o == m {
            // reconstruct: catch-alls and action counts
            let (mut ci, mut co) = (n, m);
            let mut c = Counts::default();
            let mut windows = 0usize;
            let mut replaced: Vec<(usize, usize, usize)> = Vec::new();
            while ci != 0 || co != 0 {
                let &(pi, po, act) = prev.get(&key(ci, co)).unwrap();
                match act {
                    A_VERBATIM => c.verbatim += 1,
                    A_RETARGET => c.retarget += 1,
                    A_LONGCALL => { c.longcall += 1; windows += 1 }
                    A_LONGCALL_CONV => c.longcall_convert += 1,
                    A_NARROW => { c.narrow += 1; windows += 1 }
                    A_WIDEN => { c.widen += 1; windows += 1 }
                    A_FILL_ZERO => c.fill_zero += 1,
                    A_END_TRIM => { c.end_trim += 1; windows += 1 }
                    A_LIT_DEL => { c.lit_del_words += 1; windows += 1 }
                    A_LIT_ADD => { c.lit_add_words += 1; windows += 1 }
                    A_DATA => c.data_bytes += ci - pi,
                    A_UNREACH_DEL => { c.unreach_del += ci - pi; windows += 1 }
                    A_BYTE_VERBATIM => c.byte_verbatim += 1,
                    A_NOP_FILL => c.nop_fill += 1,
                    A_NOP_UNFILL => { c.nop_unfill += 1; windows += 1 }
                    A_REPLACE | A_SKIP_IN | A_SKIP_OUT => {
                        if let Some(last) = replaced.last_mut() {
                            if last.0 == ci { last.0 = pi; last.1 += ci - pi; last.2 += co - po; }
                            else { replaced.push((pi, ci - pi, co - po)); }
                        } else {
                            replaced.push((pi, ci - pi, co - po));
                        }
                    }
                    _ => {}
                }
                ci = pi;
                co = po;
            }
            replaced.reverse();
            return if replaced.is_empty() {
                Verdict::Reconciled(c, windows)
            } else {
                Verdict::Dirty { cost: d, replaced }
            };
        }
        let push = |i2: usize, o2: usize, nd: u32, act: u8, dist: &mut HashMap<u64, u32>, prev: &mut HashMap<u64, (usize, usize, u8)>, heap: &mut BinaryHeap<(std::cmp::Reverse<u32>, usize, usize)>| {
            if i2 <= n && o2 <= m && nd < dist.get(&key(i2, o2)).copied().unwrap_or(u32::MAX) {
                dist.insert(key(i2, o2), nd);
                prev.insert(key(i2, o2), (i, o, act));
                heap.push((std::cmp::Reverse(nd), i2, o2));
            }
        };
        match if i < n { inp.region_at(i) } else { Region::Code } {
            Region::Literal(le) => {
                if i + 4 <= le.min(n) {
                    if o + 4 <= m && lit_word_matches(inp, i, &out[o..o + 4]) {
                        push(i + 4, o + 4, d, A_VERBATIM, &mut dist, &mut prev, &mut heap);
                    }
                    // ta_remove_literal
                    push(i + 4, o, d + C_KNOWN, A_LIT_DEL, &mut dist, &mut prev, &mut heap);
                }
                // ta_add_literal: a moved literal lands here (any value);
                // slightly dearer than delete so drift pairs don't tie
                if o + 4 <= m {
                    push(i, o + 4, d + 2 * C_KNOWN, A_LIT_ADD, &mut dist, &mut prev, &mut heap);
                }
                // alignment fill at literal-block edges (compensating
                // ta_fill when section alignment > 4)
                if o < m && out[o] == 0 {
                    push(i, o + 1, d + C_KNOWN, A_FILL_ZERO, &mut dist, &mut prev, &mut heap);
                }
                continue;
            }
            Region::Data(de) => {
                // raw bytes: byte-match (masked ok) only
                if i < n && o < m && (inp.mask[i] || inb[i] == out[o]) {
                    push(i + 1, o + 1, d, A_DATA, &mut dist, &mut prev, &mut heap);
                }
                let _ = de;
                // fall through to catch-alls below
            }
            Region::Unreach(_ue) => {
                // ta_fill: delete bytes / insert zeros at EBB ends
                if i < n {
                    push(i + 1, o, d, A_UNREACH_DEL, &mut dist, &mut prev, &mut heap);
                }
                if o < m && out[o] == 0 {
                    push(i, o + 1, d, A_FILL_ZERO, &mut dist, &mut prev, &mut heap);
                }
                if i < n && o < m && (inp.mask[i] || inb[i] == out[o]) {
                    push(i + 1, o + 1, d, A_VERBATIM, &mut dist, &mut prev, &mut heap);
                }
                continue;
            }
            Region::Code => {}
        }
        // ta_fill insertion at an EBB-end flex point: zeros land in the
        // output with no input counterpart
        if inp.flex_points.contains(&i) && o < m && out[o] == 0 {
            push(i, o + 1, d + C_KNOWN, A_FILL_ZERO, &mut dist, &mut prev, &mut heap);
        }
        let li = (i < n).then(|| insn_len(inb[i]).filter(|l| i + l <= n)).flatten();
        let lo = (o < m).then(|| insn_len(out[o]).filter(|l| o + l <= m)).flatten();
        // longcall first: the l32r slot is reloc-masked, so the masked
        // same-length compare would silently eat l32r-vs-anything and
        // orphan the callx
        if let Some((ia, oa, conv)) = longcall_match(&inb[i.min(n)..], &out[o.min(m)..]) {
            let act = if conv { A_LONGCALL_CONV } else { A_LONGCALL };
            push(i + ia, o + oa, d + C_KNOWN, act, &mut dist, &mut prev, &mut heap);
        }
        if let (Some(li), Some(lo)) = (li, lo) {
            if li == lo {
                let fb3;
                let fb: &[u8] = if li == 3 {
                    fb3 = free_bits(&inb[i..i + 3]);
                    &fb3
                } else {
                    &free_bits_2(&inb[i..i + 2])[..]
                };
                let mut clean = true;
                let mut pcrel = false;
                for k in 0..li {
                    let diff = inb[i + k] ^ out[o + k];
                    if diff == 0 || inp.mask[i + k] {
                        continue;
                    }
                    if diff & !fb[k] == 0 {
                        pcrel = true;
                        continue;
                    }
                    clean = false;
                    break;
                }
                if clean {
                    push(i + li, o + lo, d, if pcrel { A_RETARGET } else { A_VERBATIM }, &mut dist, &mut prev, &mut heap);
                }
            }
            if li == 3 && lo == 2 {
                let loose = inp.mask[i..i + 3].iter().any(|&m| m);
                if narrow_pair_ok(&inb[i..i + 3], &out[o..o + 2], loose) {
                    push(i + 3, o + 2, d + C_KNOWN, A_NARROW, &mut dist, &mut prev, &mut heap);
                }
            }
            if li == 2 && lo == 3 {
                let loose = inp.mask[i..i + 2].iter().any(|&m| m);
                if widen_pair_ok(&inb[i..i + 2], &out[o..o + 3], loose) {
                    push(i + 2, o + 3, d + C_KNOWN, A_WIDEN, &mut dist, &mut prev, &mut heap);
                }
            }
        }
        // diagnostics: nop insertion/removal are NOT elf32-xtensa.c
        // transforms; costed above every source rule so they only appear
        // when nothing grounded explains the bytes
        if let Some(li) = li {
            if is_nop3(&inb[i..]) || is_nop2(&inb[i..]) {
                push(i + li, o, d + C_NOP_DIAG, A_NOP_UNFILL, &mut dist, &mut prev, &mut heap);
            }
        }
        if let Some(lo) = lo {
            if is_nop3(&out[o..]) || is_nop2(&out[o..]) {
                push(i, o + lo, d + C_NOP_DIAG, A_NOP_FILL, &mut dist, &mut prev, &mut heap);
            }
        }
        // byte-granular verbatim: ld's copy loop moves bytes, not insns;
        // equal bytes advance even where the insn decoder can't parse
        // (unmarked padding straddles). Dearer than insn verbatim so
        // structured parses stay preferred.
        if i < n && o < m && (inp.mask[i] || inb[i] == out[o]) {
            push(i + 1, o + 1, d + 2, A_BYTE_VERBATIM, &mut dist, &mut prev, &mut heap);
        }
        // section-tail fill: trailing zeros in output, trailing trim of input
        if o < m && i == n && out[o] == 0 {
            push(i, o + 1, d, A_FILL_ZERO, &mut dist, &mut prev, &mut heap);
        }
        if i < n && o == m {
            push(n, m, d + C_KNOWN, A_END_TRIM, &mut dist, &mut prev, &mut heap);
        }
        // catch-alls (byte granularity)
        if i < n && o < m {
            push(i + 1, o + 1, d + C_REPLACE, A_REPLACE, &mut dist, &mut prev, &mut heap);
        }
        if i < n {
            push(i + 1, o, d + C_SKIP, A_SKIP_IN, &mut dist, &mut prev, &mut heap);
        }
        if o < m {
            push(i, o + 1, d + C_SKIP, A_SKIP_OUT, &mut dist, &mut prev, &mut heap);
        }
    }
    Verdict::Refused { in_off: 0, out_off: 0, reason: "no path".into() }
}

fn walk(inp: &InputSec, out: &[u8]) -> Verdict {
    let mut c = Counts::default();
    let mut windows = 0usize;
    match walk_greedy(inp, out, &mut c, &mut windows) {
        Ok(()) => Verdict::Reconciled(c, windows),
        Err(_) => walk_dijkstra(inp, out), // greedy failed: weighted full search
    }
}

/// Fast path: single greedy parse with the exact source rules. Anything
/// it can't explain falls back to the Dijkstra search, so this only has
/// to handle the common shapes, not be complete.
fn walk_greedy(
    inp: &InputSec,
    out: &[u8],
    c: &mut Counts,
    windows: &mut usize,
) -> Result<(), (usize, usize, String)> {
    let inb = &inp.bytes;
    let mut i = 0usize;
    let mut o = 0usize;
    loop {
        if i < inb.len() {
            match inp.region_at(i) {
                // literal region: word-wise positional match. A masked
                // word (has a reloc) matches anything; an unmasked word
                // must match by value or it was deleted. Insertions
                // (ta_add_literal) are ambiguous locally -> Dijkstra.
                Region::Literal(le) => {
                    let mut in_window = false;
                    while i + 4 <= le.min(inb.len()) {
                        let matches = o + 4 <= out.len() && lit_word_matches(inp, i, &out[o..o + 4]);
                        if matches {
                            c.verbatim += 1;
                            i += 4;
                            o += 4;
                            in_window = false;
                        } else {
                            c.lit_del_words += 1;
                            if !in_window {
                                *windows += 1;
                                in_window = true;
                            }
                            i += 4;
                        }
                    }
                    i = le.min(inb.len());
                    continue;
                }
                // data-in-text (jump tables): raw bytes, never transformed
                Region::Data(de) => {
                    let de = de.min(inb.len());
                    while i < de {
                        if o < out.len() && (inp.mask[i] || inb[i] == out[o]) {
                            c.data_bytes += 1;
                            i += 1;
                            o += 1;
                        } else {
                            return Err((i, o, "data-range mismatch".into()));
                        }
                    }
                    continue;
                }
                // unreachable region: ta_fill deletes bytes / inserts
                // zeros. Deterministic heuristic; mismatch cascades fall
                // back to the full search.
                Region::Unreach(ue) => {
                    let ue = ue.min(inb.len());
                    let mut deleted = false;
                    while i < ue {
                        if o < out.len() && (inp.mask[i] || inb[i] == out[o]) {
                            c.verbatim += 1;
                            i += 1;
                            o += 1;
                        } else if o < out.len() && out[o] == 0 {
                            c.fill_zero += 1;
                            o += 1;
                        } else {
                            c.unreach_del += 1;
                            deleted = true;
                            i += 1;
                        }
                    }
                    if deleted {
                        *windows += 1;
                    }
                    continue;
                }
                Region::Code => {}
            }
        }

        match (i < inb.len(), o < out.len()) {
            (false, false) => return Ok(()),
            (false, true) => {
                // output-only tail: zero fill (ta_fill removed<0 zeros)
                if out[o] == 0 {
                    o += 1;
                    c.fill_zero += 1;
                    continue;
                }
                return Err((i, o, "trailing output bytes".into()));
            }
            (true, false) => {
                // input-only tail: EBB-end fill removal (one window);
                // sizes were pre-sliced from the map, so consuming the
                // remainder is conservation-safe
                c.end_trim += 1;
                *windows += 1;
                i = inb.len();
                continue;
            }
            (true, true) => {}
        }

        // ta_fill zeros at an EBB-end flex point (size-0 unreachable
        // entry): eat the zero run; over-eating (zeros that belong to a
        // following insn like isync 00 20 00) cascades into the full
        // search, which splits correctly
        if inp.flex_points.contains(&i) && out[o] == 0 {
            let mut run = 0;
            while o + run < out.len() && out[o + run] == 0 && run < 16 {
                run += 1;
            }
            c.fill_zero += run;
            o += run;
            continue;
        }

        // longcall first: l32r slot is reloc-masked; masked compare would
        // silently eat l32r-vs-call and orphan the callx
        if let Some((ia, oa, conv)) = longcall_match(&inb[i..], &out[o..]) {
            if conv {
                c.longcall_convert += 1;
            } else {
                c.longcall += 1;
                *windows += 1;
            }
            i += ia;
            o += oa;
            continue;
        }

        let li = insn_len(inb[i]).filter(|l| i + l <= inb.len()).unwrap_or(0);
        let lo = insn_len(out[o]).filter(|l| o + l <= out.len()).unwrap_or(0);

        // same length: verbatim modulo input reloc mask / pc-rel free bits
        if li != 0 && li == lo {
            let fb3;
            let fb: &[u8] = if li == 3 {
                fb3 = free_bits(&inb[i..i + 3]);
                &fb3
            } else {
                &free_bits_2(&inb[i..i + 2])[..]
            };
            let mut clean = true;
            let mut pcrel = false;
            for k in 0..li {
                let diff = inb[i + k] ^ out[o + k];
                if diff == 0 || inp.mask[i + k] {
                    continue;
                }
                if diff & !fb[k] == 0 {
                    pcrel = true;
                    continue;
                }
                clean = false;
                break;
            }
            if clean {
                if pcrel {
                    c.retarget += 1
                } else {
                    c.verbatim += 1
                }
                i += li;
                o += lo;
                continue;
            }
        }
        // exact pair-table narrowing / widening
        if li == 3 && lo == 2 {
            let loose = inp.mask[i..i + 3].iter().any(|&m| m);
            if narrow_pair_ok(&inb[i..i + 3], &out[o..o + 2], loose) {
                c.narrow += 1;
                *windows += 1;
                i += 3;
                o += 2;
                continue;
            }
        }
        if li == 2 && lo == 3 {
            let loose = inp.mask[i..i + 2].iter().any(|&m| m);
            if widen_pair_ok(&inb[i..i + 2], &out[o..o + 3], loose) {
                c.widen += 1;
                *windows += 1;
                i += 2;
                o += 3;
                continue;
            }
        }
        // last resort before failing: byte-granular verbatim (ld copies
        // bytes, not insns -- unmarked padding can straddle insn decode)
        if inb[i] == out[o] || inp.mask[i] {
            c.byte_verbatim += 1;
            i += 1;
            o += 1;
            continue;
        }
        return Err((i, o, format!(
            "unexplained li={li} lo={lo} in_op0={:x} out_op0={:x} | in={:02x?} out={:02x?}",
            inb[i] & 0xF,
            out[o] & 0xF,
            &inb[i..(i + li).min(inb.len())],
            &out[o..(o + lo).min(out.len())]
        )));
    }
}

// ---------- driver ----------

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut map_p, mut elf_p, mut limit, mut verbose, mut filter) =
        (None::<PathBuf>, None::<PathBuf>, usize::MAX, false, None::<String>);
    let mut path_map = Vec::<(String, String)>::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--map" => map_p = args.next().map(Into::into),
            "--elf" => elf_p = args.next().map(Into::into),
            "--limit" => limit = args.next().and_then(|s| s.parse().ok()).unwrap_or(usize::MAX),
            "--filter" => filter = args.next(),
            "--path-map" => {
                if let Some((f, t)) = args.next().and_then(|s| s.split_once('=').map(|(a, b)| (a.to_string(), b.to_string()))) {
                    path_map.push((f, t));
                }
            }
            "-v" => verbose = true,
            other => {
                eprintln!("unknown arg {other}");
                std::process::exit(2);
            }
        }
    }
    let (map_p, elf_p) = (map_p.expect("--map"), elf_p.expect("--elf"));
    let map_text = std::fs::read_to_string(&map_p).expect("read map");
    let elf_data = std::fs::read(&elf_p).expect("read elf");
    let elf = object::File::parse(&*elf_data).expect("parse elf");

    let mut secs = parse_map(&map_text);
    if let Some(f) = &filter {
        secs.retain(|s| s.in_name.contains(f.as_str()) || s.obj.contains(f.as_str()));
    }
    eprintln!("{} relaxed sections in map", secs.len());

    // unique-address symbol table of the linked image, for literal-word
    // value checks (at overlay time this is base.elf's symtab)
    let mut out_syms: HashMap<String, u64> = HashMap::new();
    let mut ambiguous: std::collections::HashSet<String> = Default::default();
    for sym in elf.symbols() {
        let Ok(name) = sym.name() else { continue };
        let addr = sym.address();
        if name.is_empty() || sym.kind() == object::SymbolKind::Section {
            continue;
        }
        match out_syms.get(name) {
            Some(&a) if a != addr => {
                ambiguous.insert(name.to_string());
            }
            _ => {
                out_syms.insert(name.to_string(), addr);
            }
        }
    }
    for name in &ambiguous {
        out_syms.remove(name);
    }
    eprintln!("{} unique-address output symbols ({} ambiguous dropped)", out_syms.len(), ambiguous.len());

    let mut reconciled = 0usize;
    let mut diag_sections = 0usize;
    let mut totals = Counts::default();
    let mut total_windows = 0usize;
    let mut refusals: HashMap<String, usize> = HashMap::new();
    let mut load_errors: HashMap<String, usize> = HashMap::new();

    for sec in secs.iter().take(limit) {
        let mut obj = sec.obj.clone();
        for (f, t) in &path_map {
            obj = obj.replace(f.as_str(), t.as_str());
        }
        if verbose {
            eprintln!("== {} :: {} ({} -> {})", obj, sec.in_name, sec.in_size, sec.out_size);
        }
        let inp = match load_input(&obj, &sec.in_name, sec.in_size, &out_syms, verbose) {
            Ok(x) => x,
            Err(e) => {
                if verbose && !e.starts_with("merge-fold") {
                    eprintln!("  LOAD-SKIP {} :: {}: {e}", sec.obj, sec.in_name);
                }
                let key = e.split(':').next().unwrap_or("?").to_string();
                *load_errors.entry(key).or_default() += 1;
                continue;
            }
        };
        // output bytes from the linked image
        let Some(out_bytes) = elf.sections().find_map(|s| {
            let (a, sz) = (s.address(), s.size());
            (sec.addr >= a && sec.addr + sec.out_size <= a + sz)
                .then(|| s.data().ok().map(|d| d[(sec.addr - a) as usize..(sec.addr - a + sec.out_size) as usize].to_vec()))
                .flatten()
        }) else {
            *load_errors.entry("no-output-bytes".into()).or_default() += 1;
            continue;
        };
        match walk(&inp, &out_bytes) {
            Verdict::Reconciled(c, w) => {
                reconciled += 1;
                if c.used_diag() {
                    diag_sections += 1;
                    if verbose {
                        eprintln!("  OK-WITH-DIAG (non-source nop rule) {c:?}");
                    }
                }
                totals.absorb(&c);
                total_windows += w;
                if verbose {
                    eprintln!("  OK {c:?} windows={w}");
                }
            }
            Verdict::Dirty { cost, replaced } => {
                *refusals.entry("dirty (catch-all path)".into()).or_default() += 1;
                if verbose {
                    eprintln!("  DIRTY cost={cost} replaced runs (in_off,in_len,out_len): {replaced:?}");
                }
            }
            Verdict::Refused { in_off, out_off, reason } => {
                if verbose {
                    eprintln!("  REFUSE @in+{in_off:#x}/out+{out_off:#x}: {reason}");
                }
                let key = reason.split('|').next().unwrap_or("?").trim().to_string();
                *refusals.entry(key).or_default() += 1;
            }
        }
    }

    let attempted = reconciled + refusals.values().sum::<usize>();
    println!("\n=== relaxwalk results ===");
    println!("attempted: {attempted}   reconciled: {reconciled} ({:.1}%)", 100.0 * reconciled as f64 / attempted.max(1) as f64);
    println!("  of which used NON-SOURCE diagnostic rules: {diag_sections}");
    println!("actions: {totals:?}");
    println!("deletion windows: {total_windows}");
    let mut r: Vec<_> = refusals.into_iter().collect();
    r.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (k, n) in r.iter().take(12) {
        println!("refused[{n}]: {k}");
    }
    let mut l: Vec<_> = load_errors.into_iter().collect();
    l.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (k, n) in l {
        println!("load-skip[{n}]: {k}");
    }
}

// ---------- tests: ground truth assembled by xtensa-esp32s3-elf-as ----------
// (crosstool-NG esp-15.2.0_20250920; bytes from readelf -x of the probe)

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
    const ORNOP: [u8; 3] = [0x10, 0x11, 0x20]; // or a1,a1,a1
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
        conv.extend_from_slice(&ORNOP);
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
        assert!(is_ornop(&ORNOP));
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
