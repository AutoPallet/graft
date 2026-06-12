//! Target-independent reconciliation engine: weighted shortest-path
//! search over (input offset, output offset) states (docs/16 §5).
//!
//! Edge generation is dispatched on the region containing the input
//! cursor; all ISA knowledge comes through [`Target`]. Costs order the
//! parses: byte-true advances are free, known transforms cheap, the
//! byte-granular fallback dearer, diagnostics and catch-alls dearest.
//! A min-cost path that needs a catch-all yields [`Verdict::Dirty`]
//! with the unexplained byte runs localized.
//!
//! The walk runs twice at most: pass 1 offers only source-grounded
//! edges (fast, and the common case on a healthy corpus); only if no
//! complete parse exists does pass 2 add diagnostic and catch-all
//! edges to localize what the alphabet can't explain.

use super::{Census, DirtyRun, InputSection, RegionKind, Verdict};
use rustc_hash::{FxHashMap, FxHashSet};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// ISA knowledge the engine consults for code regions. Everything here
/// answers "could these input bytes have become those output bytes" —
/// never "what would ld decide".
pub trait Target {
    /// Instruction length from its first byte; None = not decodable.
    fn insn_len(&self, b0: u8) -> Option<usize>;
    /// Per-byte free-bit mask for pc-relative fields the linker
    /// retargets in place (docs/16 §3); all-zero when none.
    fn free_bits(&self, insn: &[u8]) -> [u8; 3];
    /// Exact-pair narrowing (3→2) preserving operand values; `loose`
    /// drops the operand checks when the input slot is relocated but
    /// keeps the pair identity.
    fn narrow_ok(&self, wide: &[u8], narrow: &[u8], loose: bool) -> bool;
    /// Exact-pair widening (2→3), same contract.
    fn widen_ok(&self, narrow: &[u8], wide: &[u8], loose: bool) -> bool;
    /// Longcall site at the head of `input` matching the head of
    /// `output`: Some((input advance, output advance, converted)).
    fn longcall(&self, input: &[u8], output: &[u8]) -> Option<(usize, usize, bool)>;
    /// Canonical nop at the head of `bytes` — diagnostic edges only.
    fn nop_len(&self, bytes: &[u8]) -> Option<usize>;
}

const COST_TRANSFORM: u32 = 1;
const COST_LIT_ADD: u32 = 2;
const COST_BYTE_VERBATIM: u32 = 2;
const COST_DIAG_NOP: u32 = 6;
const COST_REPLACE: u32 = 12;
const COST_SKIP: u32 = 16;
/// Backstop against pathological state growth; never fired on the
/// deploy corpus once the rules were complete.
const STATE_CAP: usize = 8_000_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Act {
    Verbatim,
    Retarget,
    Longcall,
    LongcallConvert,
    Narrow,
    Widen,
    FillZero,
    UnreachKeep,
    UnreachDel,
    LitKeep,
    LitDel,
    LitAdd,
    Data,
    ByteVerbatim,
    EndTrim,
    NopFill,
    NopUnfill,
    Replace,
    SkipIn,
    SkipOut,
}

impl Act {
    fn is_catchall(self) -> bool {
        matches!(self, Act::Replace | Act::SkipIn | Act::SkipOut)
    }
}

pub fn reconcile<T: Target>(input: &InputSection, out: &[u8], target: &T) -> Verdict {
    match walk(input, out, target, false) {
        Some(path) => verdict(&path),
        None => match walk(input, out, target, true) {
            Some(path) => verdict(&path),
            None => Verdict::Refused("state cap"),
        },
    }
}

fn key(i: usize, o: usize) -> u64 {
    (i as u64) << 32 | o as u64
}

/// Min-cost parse as forward edge list `(i, o, act)`; the final entry
/// is a sentinel at the goal state. None = no complete parse with the
/// offered edges (normal for pass 1) or state cap hit.
fn walk<T: Target>(
    inp: &InputSection,
    out: &[u8],
    t: &T,
    catchall: bool,
) -> Option<Vec<(usize, usize, Act)>> {
    let inb = &inp.bytes;
    let in_len = inb.len();
    let out_len = out.len();

    // Per-byte region map: 0 code, 1 literal, 2 unreachable, 3 data;
    // rend = end of the containing region. Section identity within the
    // walk is positional, so a flat map beats interval search.
    let mut rkind = vec![0u8; in_len];
    let mut rend = vec![0u32; in_len];
    // Literal-block boundaries: ta_fill compensation when section
    // alignment > 4 lands zeros at pool edges (docs/16 §5).
    let mut lit_edges: FxHashSet<usize> = FxHashSet::default();
    for (range, kind) in &inp.regions {
        let s = range.start.min(in_len);
        let e = range.end.min(in_len);
        if *kind == RegionKind::Literal {
            lit_edges.insert(s);
            lit_edges.insert(e);
        }
        let code = match kind {
            RegionKind::Literal => 1,
            RegionKind::Unreachable => 2,
            RegionKind::Data => 3,
        };
        for b in s..e {
            rkind[b] = code;
            rend[b] = e as u32;
        }
    }

    let goal = key(in_len, out_len);
    let mut dist: FxHashMap<u64, u32> = FxHashMap::default();
    let mut prev: FxHashMap<u64, (u32, u32, Act)> = FxHashMap::default();
    let mut heap: BinaryHeap<(Reverse<u32>, u64)> = BinaryHeap::new();
    dist.insert(key(0, 0), 0);
    heap.push((Reverse(0), key(0, 0)));

    while let Some((Reverse(d), k)) = heap.pop() {
        if dist.get(&k) != Some(&d) {
            continue; // stale heap entry
        }
        if k == goal {
            let mut path = vec![(in_len, out_len, Act::Verbatim)]; // sentinel
            let mut cur = goal;
            while cur != key(0, 0) {
                let &(pi, po, act) = prev.get(&cur).unwrap();
                path.push((pi as usize, po as usize, act));
                cur = key(pi as usize, po as usize);
            }
            path.reverse();
            return Some(path);
        }
        if dist.len() > STATE_CAP {
            return None;
        }
        let (i, o) = ((k >> 32) as usize, (k & 0xFFFF_FFFF) as usize);

        let mut push = |i2: usize, o2: usize, nd: u32, act: Act| {
            let k2 = key(i2, o2);
            if dist.get(&k2).is_none_or(|&dd| nd < dd) {
                dist.insert(k2, nd);
                prev.insert(k2, (i as u32, o as u32, act));
                heap.push((Reverse(nd), k2));
            }
        };

        // --- input exhausted: output remainder must be zeros ⇒ ta_fill ---
        if i == in_len {
            if out[o] == 0 {
                push(i, o + 1, d, Act::FillZero);
            }
            if catchall {
                push(i, o + 1, d + COST_SKIP, Act::SkipOut);
            }
            continue;
        }

        // Deletion-style edges stay available when the output is
        // exhausted (a fully-folded pool is still word-wise lit-del);
        // everything that reads out[o] is guarded.
        match rkind[i] {
            // literal pool: word granularity
            1 => {
                let e = rend[i] as usize;
                if i + 4 <= e {
                    if o + 4 <= out_len && lit_word_ok(inp, i, &out[o..o + 4]) {
                        push(i + 4, o + 4, d, Act::LitKeep);
                    }
                    push(i + 4, o, d + COST_TRANSFORM, Act::LitDel);
                    if o + 4 <= out_len {
                        // moved literal: value arbitrary (reloc-carried)
                        push(i, o + 4, d + COST_LIT_ADD, Act::LitAdd);
                    }
                } else if o < out_len && (inb[i] == out[o] || inp.mask[i]) {
                    // ragged sub-word pool tail
                    push(i + 1, o + 1, d, Act::Data);
                }
            }
            // unreachable: EBB-end flex region
            2 => {
                push(i + 1, o, d, Act::UnreachDel);
                if o < out_len {
                    if inb[i] == out[o] || inp.mask[i] {
                        push(i + 1, o + 1, d, Act::UnreachKeep);
                    }
                    if out[o] == 0 {
                        push(i, o + 1, d, Act::FillZero);
                    }
                }
            }
            // raw data: byte-true only
            3 => {
                if o < out_len && (inb[i] == out[o] || inp.mask[i]) {
                    push(i + 1, o + 1, d, Act::Data);
                }
            }
            // instruction stream
            _ if o == out_len => {
                // input remainder: ta_fill deletion at the section-end EBB
                push(i + 1, o, d + COST_TRANSFORM, Act::EndTrim);
            }
            _ => {
                if let Some((ia, oa, conv)) = t.longcall(&inb[i..], &out[o..]) {
                    let act = if conv { Act::LongcallConvert } else { Act::Longcall };
                    if i + ia <= in_len && o + oa <= out_len {
                        push(i + ia, o + oa, d + COST_TRANSFORM, act);
                    }
                }
                if let Some(len) = t.insn_len(inb[i])
                    && i + len <= in_len
                {
                    let loose = inp.mask[i..i + len].iter().any(|&m| m);
                    if o + len <= out_len {
                        let fb = t.free_bits(&inb[i..i + len]);
                        let mut clean = true;
                        let mut ok = true;
                        for x in 0..len {
                            let (a, b) = (inb[i + x], out[o + x]);
                            if a == b || inp.mask[i + x] {
                                continue;
                            }
                            clean = false;
                            if (a ^ b) & !fb[x] != 0 {
                                ok = false;
                                break;
                            }
                        }
                        if ok {
                            let act = if clean { Act::Verbatim } else { Act::Retarget };
                            push(i + len, o + len, d, act);
                        }
                    }
                    if len == 3
                        && o + 2 <= out_len
                        && t.narrow_ok(&inb[i..i + 3], &out[o..o + 2], loose)
                    {
                        push(i + 3, o + 2, d + COST_TRANSFORM, Act::Narrow);
                    }
                    if len == 2
                        && o + 3 <= out_len
                        && t.widen_ok(&inb[i..i + 2], &out[o..o + 3], loose)
                    {
                        push(i + 2, o + 3, d + COST_TRANSFORM, Act::Widen);
                    }
                }
                // ta_fill zero insertion at a flex point (size-0
                // UNREACHABLE entry whose range is empty)
                if inp.flex_points.contains(&i) && out[o] == 0 {
                    push(i, o + 1, d + COST_TRANSFORM, Act::FillZero);
                }
                // ld's copy loop is byte-oriented; equal bytes advance
                // even across undecodable unmarked padding (docs/16 §2)
                if inb[i] == out[o] || inp.mask[i] {
                    push(i + 1, o + 1, d + COST_BYTE_VERBATIM, Act::ByteVerbatim);
                }
                if catchall {
                    if let Some(nl) = t.nop_len(&out[o..]) {
                        push(i, o + nl, d + COST_DIAG_NOP, Act::NopFill);
                    }
                    if let Some(nl) = t.nop_len(&inb[i..]) {
                        push(i + nl, o, d + COST_DIAG_NOP, Act::NopUnfill);
                    }
                }
            }
        }
        // compensating ta_fill at a literal-block edge (any region)
        if o < out_len && lit_edges.contains(&i) && out[o] == 0 {
            push(i, o + 1, d + COST_TRANSFORM, Act::FillZero);
        }
        if catchall {
            push(i + 1, o, d + COST_SKIP, Act::SkipIn);
            if o < out_len {
                push(i + 1, o + 1, d + COST_REPLACE, Act::Replace);
                push(i, o + 1, d + COST_SKIP, Act::SkipOut);
            }
        }
    }
    None
}

fn lit_word_ok(inp: &InputSection, i: usize, out_word: &[u8]) -> bool {
    if let Some(&v) = inp.lit_expect.get(&i) {
        // value-known word: the strictest and only trustworthy check
        u32::from_le_bytes(out_word.try_into().unwrap()) == v
    } else if inp.mask[i..i + 4].iter().any(|&m| m) {
        true // relocated, value unknowable here
    } else {
        inp.bytes[i..i + 4] == *out_word
    }
}

fn verdict(path: &[(usize, usize, Act)]) -> Verdict {
    let mut c = Census::default();
    let mut runs: Vec<DirtyRun> = Vec::new();
    for w in path.windows(2) {
        let (i, o, act) = w[0];
        let (ni, no, _) = w[1];
        match act {
            Act::Verbatim => c.verbatim += 1,
            Act::Retarget => c.retarget += 1,
            Act::Longcall => c.longcall += 1,
            Act::LongcallConvert => c.longcall_convert += 1,
            Act::Narrow => c.narrow += 1,
            Act::Widen => c.widen += 1,
            Act::FillZero => c.fill_zero += 1,
            Act::UnreachKeep => c.unreach_keep += 1,
            Act::UnreachDel => c.unreach_del += 1,
            Act::LitKeep => c.lit_keep_words += 1,
            Act::LitDel => c.lit_del_words += 1,
            Act::LitAdd => c.lit_add_words += 1,
            Act::Data => c.data_bytes += 1,
            Act::ByteVerbatim => c.byte_verbatim += 1,
            Act::EndTrim => c.end_trim += 1,
            Act::NopFill => c.nop_fill += 1,
            Act::NopUnfill => c.nop_unfill += 1,
            Act::Replace => c.replace += 1,
            Act::SkipIn => c.skip_in += 1,
            Act::SkipOut => c.skip_out += 1,
        }
        if act.is_catchall() {
            let (din, dout) = (ni - i, no - o);
            match runs.last_mut() {
                Some(r) if r.in_off + r.in_len == i => {
                    r.in_len += din;
                    r.out_len += dout;
                }
                _ => runs.push(DirtyRun { in_off: i, in_len: din, out_len: dout }),
            }
        }
    }
    if c.replace + c.skip_in + c.skip_out > 0 {
        Verdict::Dirty(c, runs)
    } else {
        Verdict::Reconciled(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relax::InputSection;
    use std::collections::{HashMap, HashSet};

    /// No-ISA target: code bytes only ever match byte-wise. Lets the
    /// engine's region machinery be tested without xtensa.
    struct Null;
    impl Target for Null {
        fn insn_len(&self, _: u8) -> Option<usize> {
            None
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

    fn input(bytes: &[u8]) -> InputSection {
        InputSection {
            bytes: bytes.to_vec(),
            mask: vec![false; bytes.len()],
            regions: Vec::new(),
            flex_points: HashSet::new(),
            lit_expect: HashMap::new(),
        }
    }

    #[test]
    fn identical_bytes_reconcile() {
        let inp = input(&[1, 2, 3, 4]);
        match reconcile(&inp, &[1, 2, 3, 4], &Null) {
            Verdict::Reconciled(c) => assert_eq!(c.byte_verbatim, 4),
            _ => panic!("expected reconciled"),
        }
    }

    #[test]
    fn masked_byte_may_differ() {
        let mut inp = input(&[1, 2, 3, 4]);
        inp.mask[2] = true;
        assert!(matches!(reconcile(&inp, &[1, 2, 99, 4], &Null), Verdict::Reconciled(_)));
    }

    #[test]
    fn mismatch_is_dirty_and_localized() {
        let inp = input(&[1, 2, 3, 4, 5, 6]);
        match reconcile(&inp, &[1, 2, 9, 9, 5, 6], &Null) {
            Verdict::Dirty(c, runs) => {
                assert_eq!(c.replace, 2);
                assert_eq!(runs.len(), 1);
                assert_eq!((runs[0].in_off, runs[0].in_len, runs[0].out_len), (2, 2, 2));
            }
            _ => panic!("expected dirty"),
        }
    }

    #[test]
    fn dead_literal_words_delete() {
        let mut inp = input(&[0xAA; 12]);
        inp.regions.push((0..12, crate::relax::RegionKind::Literal));
        match reconcile(&inp, &[0xAA; 4], &Null) {
            Verdict::Reconciled(c) => {
                assert_eq!(c.lit_del_words, 2);
                assert_eq!(c.lit_keep_words, 1);
            }
            _ => panic!("expected reconciled"),
        }
    }

    #[test]
    fn lit_expect_pins_word_value() {
        // masked word would match anything — the known value vetoes the
        // positional word match; a wrong value still reconciles, but
        // only as delete+insert (the DP-intersection layer's ambiguity)
        let mut inp = input(&[0, 0, 0, 0]);
        inp.mask.iter_mut().for_each(|m| *m = true);
        inp.regions.push((0..4, crate::relax::RegionKind::Literal));
        inp.lit_expect.insert(0, 0x40001234);
        match reconcile(&inp, &0x40001234u32.to_le_bytes(), &Null) {
            Verdict::Reconciled(c) => assert_eq!(c.lit_keep_words, 1),
            _ => panic!("expected reconciled"),
        }
        match reconcile(&inp, &0x40005678u32.to_le_bytes(), &Null) {
            Verdict::Reconciled(c) => {
                assert_eq!(c.lit_keep_words, 0);
                assert_eq!((c.lit_del_words, c.lit_add_words), (1, 1));
            }
            _ => panic!("expected reconciled via del+add"),
        }
    }

    #[test]
    fn unreachable_pad_resizes() {
        let mut inp = input(&[1, 2, 0, 0, 0, 5, 6]);
        inp.regions.push((2..5, crate::relax::RegionKind::Unreachable));
        // pad shrinks 3 → 1
        assert!(matches!(reconcile(&inp, &[1, 2, 0, 5, 6], &Null), Verdict::Reconciled(_)));
        // pad grows 3 → 5
        assert!(matches!(
            reconcile(&inp, &[1, 2, 0, 0, 0, 0, 0, 5, 6], &Null),
            Verdict::Reconciled(_)
        ));
    }
}
