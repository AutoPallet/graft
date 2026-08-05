//! Target-independent reconciliation engine: weighted shortest-path
//! search over (input offset, output offset) states (docs/16 §5).
//!
//! Edge generation lives in ONE place ([`for_each_edge`]), dispatched
//! on the region containing the input cursor; all ISA knowledge comes
//! through [`Target`]. Costs order the parses: byte-true advances are
//! free, known transforms cheap, the byte-granular fallback dearer,
//! diagnostics and catch-alls dearest. A min-cost path that needs a
//! catch-all yields [`Verdict::Dirty`] with the unexplained byte runs
//! localized.
//!
//! The walk runs twice at most: pass 1 offers only source-grounded
//! edges (fast, and the common case on a healthy corpus); only if no
//! complete parse exists does pass 2 add diagnostic and catch-all
//! edges to localize what the alphabet can't explain.
//!
//! [`translations`] is the DP-intersection layer (docs/16 §8): it
//! enumerates ALL minimum-cost source-grounded parses and intersects
//! their per-byte verdicts — an input offset is translatable only if
//! every surviving parse maps it identically. Disagreement refuses the
//! offset, never guesses. The matching rules themselves are also
//! mask-granular (operand checks are skipped only for reloc-written
//! bytes) and longcall edges exist only at ASM_EXPAND-marked sites —
//! both shrink the space of bogus parses that could ever compete on
//! cost with the true one.

use super::{Census, DirtyRun, Fate, FateCell, InputSection, RegionKind, Verdict};
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
    /// Exact-pair narrowing (3→2) preserving operand values. `in_mask`
    /// is the input slot's per-byte reloc mask: operand checks reading
    /// a masked byte are skipped (the linker wrote it), checks over
    /// unmasked bytes — register fields, typically — always hold.
    fn narrow_ok(&self, wide: &[u8], narrow: &[u8], in_mask: &[bool]) -> bool;
    /// Exact-pair widening (2→3), same contract.
    fn widen_ok(&self, narrow: &[u8], wide: &[u8], in_mask: &[bool]) -> bool;
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
/// deploy corpus.
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

/// The degenerate (zero-transform) walk: byte-compare modulo reloc
/// masks, equal sizes required. With equal sizes the min-cost path is
/// replace-only, so mismatch runs fall out directly — O(n) instead of
/// a Dijkstra over the catch-all lattice (which is pathological on big
/// mismatching sections). `Ok(())` means the input provably landed at
/// this output location unchanged; `Err` localizes the dirt.
pub fn masked_compare(input: &InputSection, out: &[u8]) -> Result<(), Vec<DirtyRun>> {
    if input.bytes.len() != out.len() {
        return Err(vec![DirtyRun { in_off: 0, in_len: input.bytes.len(), out_len: out.len() }]);
    }
    let mut runs: Vec<DirtyRun> = Vec::new();
    for (k, (a, b)) in input.bytes.iter().zip(out).enumerate() {
        if a == b || input.mask[k] {
            continue;
        }
        match runs.last_mut() {
            Some(r) if r.in_off + r.in_len == k => {
                r.in_len += 1;
                r.out_len += 1;
            }
            _ => runs.push(DirtyRun { in_off: k, in_len: 1, out_len: 1 }),
        }
    }
    if runs.is_empty() { Ok(()) } else { Err(runs) }
}

fn key(i: usize, o: usize) -> u64 {
    (i as u64) << 32 | o as u64
}

fn unkey(k: u64) -> (usize, usize) {
    ((k >> 32) as usize, (k & 0xFFFF_FFFF) as usize)
}

/// Precomputed per-section context shared by every pass.
struct Ctx<'a, T: Target> {
    inp: &'a InputSection,
    out: &'a [u8],
    t: &'a T,
    /// Per-byte region map: 0 code, 1 literal, 2 unreachable, 3 data.
    /// Section identity within the walk is positional, so a flat map
    /// beats interval search.
    rkind: Vec<u8>,
    /// End of the region containing each byte (literal word ops stop
    /// at their pool's edge).
    rend: Vec<u32>,
    /// Literal-block boundaries: ta_fill compensation when section
    /// alignment > 4 lands zeros at pool edges (docs/16 §5).
    lit_edges: FxHashSet<usize>,
    catchall: bool,
}

fn build_ctx<'a, T: Target>(
    inp: &'a InputSection,
    out: &'a [u8],
    t: &'a T,
    catchall: bool,
) -> Ctx<'a, T> {
    let in_len = inp.bytes.len();
    let mut rkind = vec![0u8; in_len];
    let mut rend = vec![0u32; in_len];
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
    Ctx { inp, out, t, rkind, rend, lit_edges, catchall }
}

/// Enumerate every edge out of state (i, o) as `f(i2, o2, cost, act)`.
/// The single edge-generator: the walk, the backward DP, and the fate
/// intersection all consume exactly this set.
fn for_each_edge<T: Target>(
    cx: &Ctx<T>,
    i: usize,
    o: usize,
    f: &mut dyn FnMut(usize, usize, u32, Act),
) {
    let inp = cx.inp;
    let inb = &inp.bytes;
    let out = cx.out;
    let in_len = inb.len();
    let out_len = out.len();

    // --- input exhausted: output remainder must be zeros ⇒ ta_fill ---
    if i == in_len {
        if o < out_len {
            if out[o] == 0 {
                f(i, o + 1, 0, Act::FillZero);
            }
            if cx.catchall {
                f(i, o + 1, COST_SKIP, Act::SkipOut);
            }
        }
        return;
    }

    // Deletion-style edges stay available when the output is
    // exhausted (a fully-folded pool is still word-wise lit-del);
    // everything that reads out[o] is guarded.
    match cx.rkind[i] {
        // literal pool: word granularity
        1 => {
            let e = cx.rend[i] as usize;
            if i + 4 <= e {
                if o + 4 <= out_len && lit_word_ok(inp, i, &out[o..o + 4]) {
                    f(i + 4, o + 4, 0, Act::LitKeep);
                }
                f(i + 4, o, COST_TRANSFORM, Act::LitDel);
                if o + 4 <= out_len {
                    // moved literal: value arbitrary (reloc-carried)
                    f(i, o + 4, COST_LIT_ADD, Act::LitAdd);
                }
            } else if o < out_len && (inb[i] == out[o] || inp.mask[i]) {
                // ragged sub-word pool tail
                f(i + 1, o + 1, 0, Act::Data);
            }
        }
        // unreachable: EBB-end flex region
        2 => {
            f(i + 1, o, 0, Act::UnreachDel);
            if o < out_len {
                if inb[i] == out[o] || inp.mask[i] {
                    f(i + 1, o + 1, 0, Act::UnreachKeep);
                }
                if out[o] == 0 {
                    f(i, o + 1, 0, Act::FillZero);
                }
            }
        }
        // raw data: byte-true only
        3 => {
            if o < out_len && (inb[i] == out[o] || inp.mask[i]) {
                f(i + 1, o + 1, 0, Act::Data);
            }
        }
        // instruction stream
        _ if o == out_len => {
            // input remainder: ta_fill deletion at the section-end EBB
            f(i + 1, o, COST_TRANSFORM, Act::EndTrim);
        }
        _ => {
            // Longcall edges only at ASM_EXPAND/ASM_SIMPLIFY-marked
            // offsets — ld's do_asm_simplify converts nowhere else.
            if inp.longcall_points.contains(&i)
                && let Some((ia, oa, conv)) = cx.t.longcall(&inb[i..], &out[o..])
            {
                let act = if conv { Act::LongcallConvert } else { Act::Longcall };
                if i + ia <= in_len && o + oa <= out_len {
                    f(i + ia, o + oa, COST_TRANSFORM, act);
                }
            }
            if let Some(len) = cx.t.insn_len(inb[i])
                && i + len <= in_len
            {
                if o + len <= out_len {
                    let fb = cx.t.free_bits(&inb[i..i + len]);
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
                        f(i + len, o + len, 0, act);
                    }
                }
                if len == 3
                    && o + 2 <= out_len
                    && cx.t.narrow_ok(&inb[i..i + 3], &out[o..o + 2], &inp.mask[i..i + 3])
                {
                    f(i + 3, o + 2, COST_TRANSFORM, Act::Narrow);
                }
                if len == 2
                    && o + 3 <= out_len
                    && cx.t.widen_ok(&inb[i..i + 2], &out[o..o + 3], &inp.mask[i..i + 2])
                {
                    f(i + 2, o + 3, COST_TRANSFORM, Act::Widen);
                }
            }
            // ta_fill zero insertion at a flex point (size-0
            // UNREACHABLE entry whose range is empty)
            if o < out_len && inp.flex_points.contains(&i) && out[o] == 0 {
                f(i, o + 1, COST_TRANSFORM, Act::FillZero);
            }
            // ld's copy loop is byte-oriented; equal bytes advance
            // even across undecodable unmarked padding (docs/16 §2)
            if o < out_len && (inb[i] == out[o] || inp.mask[i]) {
                f(i + 1, o + 1, COST_BYTE_VERBATIM, Act::ByteVerbatim);
            }
            if cx.catchall && o < out_len {
                if let Some(nl) = cx.t.nop_len(&out[o..]) {
                    f(i, o + nl, COST_DIAG_NOP, Act::NopFill);
                }
                if let Some(nl) = cx.t.nop_len(&inb[i..]) {
                    f(i + nl, o, COST_DIAG_NOP, Act::NopUnfill);
                }
            }
        }
    }
    // compensating ta_fill at a literal-block edge (any region)
    if o < out_len && cx.lit_edges.contains(&i) && out[o] == 0 {
        f(i, o + 1, COST_TRANSFORM, Act::FillZero);
    }
    if cx.catchall {
        f(i + 1, o, COST_SKIP, Act::SkipIn);
        if o < out_len {
            f(i + 1, o + 1, COST_REPLACE, Act::Replace);
            f(i, o + 1, COST_SKIP, Act::SkipOut);
        }
    }
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
    let cx = build_ctx(inp, out, t, catchall);
    let (in_len, out_len) = (inp.bytes.len(), out.len());
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
        let (i, o) = unkey(k);
        for_each_edge(&cx, i, o, &mut |i2, o2, c, act| {
            let k2 = key(i2, o2);
            let nd = d + c;
            if dist.get(&k2).is_none_or(|&dd| nd < dd) {
                dist.insert(k2, nd);
                prev.insert(k2, (i as u32, o as u32, act));
                heap.push((Reverse(nd), k2));
            }
        });
    }
    None
}

/// DP-intersection (docs/16 §8): per-input-byte fate agreed by EVERY
/// minimum-cost source-grounded parse, or [`FateCell::Ambiguous`]
/// where parses disagree. None = no source-grounded parse exists (the
/// section is dirty/refused; nothing is translatable).
///
/// Forward Dijkstra runs to exhaustion (no goal early-exit), a
/// backward DP over the explored states (topological by decreasing
/// i+o — every edge strictly advances at least one cursor) gives
/// min-cost-to-goal, and an edge lies on some min-cost parse iff
/// `dist[from] + cost + bdist[to] == dist[goal]`.
pub fn translations<T: Target>(
    inp: &InputSection,
    out: &[u8],
    t: &T,
) -> Option<Vec<FateCell>> {
    let cx = build_ctx(inp, out, t, false);
    let (in_len, out_len) = (inp.bytes.len(), out.len());
    let goal = key(in_len, out_len);

    // forward, exhaustive
    let mut dist: FxHashMap<u64, u32> = FxHashMap::default();
    let mut heap: BinaryHeap<(Reverse<u32>, u64)> = BinaryHeap::new();
    dist.insert(key(0, 0), 0);
    heap.push((Reverse(0), key(0, 0)));
    while let Some((Reverse(d), k)) = heap.pop() {
        if dist.get(&k) != Some(&d) {
            continue;
        }
        if dist.len() > STATE_CAP {
            return None;
        }
        let (i, o) = unkey(k);
        for_each_edge(&cx, i, o, &mut |i2, o2, c, _| {
            let k2 = key(i2, o2);
            let nd = d + c;
            if dist.get(&k2).is_none_or(|&dd| nd < dd) {
                dist.insert(k2, nd);
                heap.push((Reverse(nd), k2));
            }
        });
    }
    let dstar = *dist.get(&goal)?;

    // backward min-cost-to-goal
    let mut states: Vec<u64> = dist.keys().copied().collect();
    states.sort_by_key(|&k| Reverse((k >> 32) + (k & 0xFFFF_FFFF)));
    let mut bdist: FxHashMap<u64, u32> = FxHashMap::default();
    bdist.insert(goal, 0);
    for &k in &states {
        if k == goal {
            continue;
        }
        let (i, o) = unkey(k);
        let mut best: Option<u32> = None;
        for_each_edge(&cx, i, o, &mut |i2, o2, c, _| {
            if let Some(&b) = bdist.get(&key(i2, o2)) {
                let v = c + b;
                if best.is_none_or(|x| v < x) {
                    best = Some(v);
                }
            }
        });
        if let Some(b) = best {
            bdist.insert(k, b);
        }
    }

    // intersect fates over every tight edge
    let mut cells: Vec<Option<FateCell>> = vec![None; in_len];
    let record = |k: usize, fate: Fate, cells: &mut Vec<Option<FateCell>>| {
        cells[k] = match cells[k] {
            None => Some(FateCell::Agreed(fate)),
            Some(FateCell::Agreed(f)) if f == fate => Some(FateCell::Agreed(f)),
            _ => Some(FateCell::Ambiguous),
        };
    };
    for (&k, &df) in &dist {
        let (i, o) = unkey(k);
        for_each_edge(&cx, i, o, &mut |i2, o2, c, act| {
            let Some(&b2) = bdist.get(&key(i2, o2)) else { return };
            if df + c + b2 != dstar {
                return; // not on any min-cost parse
            }
            match act {
                // 1:1 byte correspondence
                Act::Verbatim
                | Act::Retarget
                | Act::ByteVerbatim
                | Act::Data
                | Act::UnreachKeep
                | Act::LitKeep => {
                    for b in i..i2 {
                        record(b, Fate::Kept((o + (b - i)) as u32), &mut cells);
                    }
                }
                // reshaped instructions: only the start has a defined
                // output offset (branch targets land on insn starts)
                Act::Narrow | Act::Widen | Act::Longcall | Act::LongcallConvert => {
                    record(i, Fate::Kept(o as u32), &mut cells);
                    for b in i + 1..i2 {
                        record(b, Fate::Interior, &mut cells);
                    }
                }
                Act::LitDel | Act::UnreachDel | Act::EndTrim => {
                    for b in i..i2 {
                        record(b, Fate::Deleted, &mut cells);
                    }
                }
                // output-only edges consume no input bytes
                Act::FillZero | Act::LitAdd => {}
                // catch-alls/diagnostics are not in the pass-1 edge set
                _ => {}
            }
            let _ = o2;
        });
    }
    // every input byte is consumed by every complete parse; an unset
    // cell would mean the edge accounting is wrong — refuse it
    Some(cells.into_iter().map(|c| c.unwrap_or(FateCell::Ambiguous)).collect())
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
        fn narrow_ok(&self, _: &[u8], _: &[u8], _: &[bool]) -> bool {
            false
        }
        fn widen_ok(&self, _: &[u8], _: &[u8], _: &[bool]) -> bool {
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
            longcall_points: HashSet::new(),
            lit_expect: HashMap::new(),
        }
    }


    /// Longcall edges are offered ONLY at ASM_EXPAND/ASM_SIMPLIFY
    /// offsets (ld's do_asm_simplify converts nowhere else). A target
    /// whose longcall matcher would fire everywhere must still refuse
    /// an unmarked site.
    #[test]
    fn longcall_gated_on_marked_offsets() {
        /// Insn-less target that "converts" input [7,7,7] → output [9].
        struct LC;
        impl Target for LC {
            fn insn_len(&self, _: u8) -> Option<usize> {
                None
            }
            fn free_bits(&self, _: &[u8]) -> [u8; 3] {
                [0; 3]
            }
            fn narrow_ok(&self, _: &[u8], _: &[u8], _: &[bool]) -> bool {
                false
            }
            fn widen_ok(&self, _: &[u8], _: &[u8], _: &[bool]) -> bool {
                false
            }
            fn longcall(&self, i: &[u8], o: &[u8]) -> Option<(usize, usize, bool)> {
                (i.len() >= 3 && i[..3] == [7, 7, 7] && !o.is_empty() && o[0] == 9)
                    .then_some((3, 1, false))
            }
            fn nop_len(&self, _: &[u8]) -> Option<usize> {
                None
            }
        }
        // Unmarked: the 3→1 shrink has no explanation → not Reconciled.
        let inp = input(&[7, 7, 7]);
        assert!(!matches!(reconcile(&inp, &[9], &LC), Verdict::Reconciled(_)));
        // Marked at offset 0: the longcall edge explains it.
        let mut inp = input(&[7, 7, 7]);
        inp.longcall_points.insert(0);
        match reconcile(&inp, &[9], &LC) {
            Verdict::Reconciled(c) => assert_eq!(c.longcall, 1),
            _ => panic!("expected reconciled at the marked site"),
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

    #[test]
    fn translations_agree_on_unique_parse() {
        let inp = input(&[1, 2, 3, 4]);
        let fates = translations(&inp, &[1, 2, 3, 4], &Null).unwrap();
        for (k, f) in fates.iter().enumerate() {
            assert_eq!(*f, FateCell::Agreed(Fate::Kept(k as u32)));
        }
    }

    #[test]
    fn translations_flag_twin_masked_literals() {
        // two identical reloc-masked words, one survives: (del w0, keep
        // w1) and (keep w0, del w1) tie at cost 1 — every byte of both
        // words is ambiguous and must refuse
        let mut inp = input(&[0xAA; 8]);
        inp.mask.iter_mut().for_each(|m| *m = true);
        inp.regions.push((0..8, crate::relax::RegionKind::Literal));
        let fates = translations(&inp, &[0xAA; 4], &Null).unwrap();
        assert!(fates.iter().all(|f| *f == FateCell::Ambiguous));
    }

    #[test]
    fn translations_pin_resolves_twin_literals() {
        // same shape, but the surviving word's value is known: only
        // the parse keeping the pinned word is min-cost-compatible…
        // for the word whose expected value matches the output
        let mut inp = input(&[0xAA; 8]);
        inp.mask.iter_mut().for_each(|m| *m = true);
        inp.regions.push((0..8, crate::relax::RegionKind::Literal));
        inp.lit_expect.insert(0, 0x11223344);
        inp.lit_expect.insert(4, 0x55667788);
        let fates = translations(&inp, &0x55667788u32.to_le_bytes(), &Null).unwrap();
        for b in 0..4 {
            assert_eq!(fates[b], FateCell::Agreed(Fate::Deleted));
        }
        for b in 4..8 {
            assert_eq!(fates[b], FateCell::Agreed(Fate::Kept((b - 4) as u32)));
        }
    }
}
