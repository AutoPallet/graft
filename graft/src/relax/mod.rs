//! Relaxation reconciliation walk (docs/16-relaxation-walk.md).
//!
//! xtensa GNU ld rewrites section interiors at link time; a positional
//! anchor `base_section_start + input_offset` is unsound for a relaxed
//! section. The walk explains every output byte as exactly one transform
//! from ld's finite vocabulary, yielding an input-offset → output-offset
//! translation for every surviving byte. Anything unexplained is Dirty:
//! the caller must refuse the translation (closure-pull/bail), never
//! guess.
//!
//! Engine/target split (docs/16 §9): [`engine`] owns the region model
//! and the weighted shortest-path search and knows nothing about any
//! ISA; [`xtensa`] reduces the ISA to const pair tables plus a few
//! byte-shape matchers, all transcribed from binutils
//! `bfd/elf32-xtensa.c` at tag `esp-2.45.0_20250920`. We transcribe
//! ld's transform *alphabet*, never its decisions.

pub mod engine;
pub mod verify;
pub mod x86;
pub mod xtensa;

use std::collections::{HashMap, HashSet};
use std::ops::Range;

/// Byte ranges of an input section that ld treats specially, classified
/// from `.xt.prop` entries (docs/16 §4). Bytes outside every region are
/// instruction stream.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegionKind {
    /// Literal pool: word-granular match/delete/insert.
    Literal,
    /// EBB-end flex region: ld deletes bytes or inserts pad zeros here.
    Unreachable,
    /// Raw data inside an exec section (jump tables): byte-equal only.
    Data,
}

/// The input side of a walk: pristine section bytes plus everything the
/// matcher may consult about them.
pub struct InputSection {
    pub bytes: Vec<u8>,
    /// Bytes covered by relocation fields; their output values may
    /// differ freely (the link wrote them).
    pub mask: Vec<bool>,
    /// Sorted, disjoint special regions; everything else is code.
    pub regions: Vec<(Range<usize>, RegionKind)>,
    /// Starts of UNREACHABLE prop entries (any size, including 0):
    /// ta_fill sites where ld may insert pad zeros (docs/16 §2).
    pub flex_points: HashSet<usize>,
    /// Literal words whose linked value is known: offset → expected
    /// output word (named-symbol R_XTENSA_32 + unique address in the
    /// linked image). Kills masked-word-eats-code (docs/16 §4).
    pub lit_expect: HashMap<usize, u32>,
}

/// Tallies over the min-cost path, one bump per edge (words for
/// literal-region edges, bytes for the other region edges, instructions
/// for code edges).
#[derive(Default, Debug, Clone)]
pub struct Census {
    pub verbatim: u64,
    pub retarget: u64,
    pub longcall: u64,
    pub longcall_convert: u64,
    pub narrow: u64,
    pub widen: u64,
    pub fill_zero: u64,
    pub unreach_keep: u64,
    pub unreach_del: u64,
    pub lit_keep_words: u64,
    pub lit_del_words: u64,
    pub lit_add_words: u64,
    pub data_bytes: u64,
    pub byte_verbatim: u64,
    pub end_trim: u64,
    /// Diagnostic-only edges — NOT in elf32-xtensa.c. Non-zero means a
    /// real case leans on a non-source rule; keep this at zero.
    pub nop_fill: u64,
    pub nop_unfill: u64,
    /// Catch-alls; any use downgrades the verdict to Dirty.
    pub replace: u64,
    pub skip_in: u64,
    pub skip_out: u64,
}

impl Census {
    pub fn absorb(&mut self, o: &Census) {
        self.verbatim += o.verbatim;
        self.retarget += o.retarget;
        self.longcall += o.longcall;
        self.longcall_convert += o.longcall_convert;
        self.narrow += o.narrow;
        self.widen += o.widen;
        self.fill_zero += o.fill_zero;
        self.unreach_keep += o.unreach_keep;
        self.unreach_del += o.unreach_del;
        self.lit_keep_words += o.lit_keep_words;
        self.lit_del_words += o.lit_del_words;
        self.lit_add_words += o.lit_add_words;
        self.data_bytes += o.data_bytes;
        self.byte_verbatim += o.byte_verbatim;
        self.end_trim += o.end_trim;
        self.nop_fill += o.nop_fill;
        self.nop_unfill += o.nop_unfill;
        self.replace += o.replace;
        self.skip_in += o.skip_in;
        self.skip_out += o.skip_out;
    }

    pub fn diagnostics(&self) -> u64 {
        self.nop_fill + self.nop_unfill
    }
}

/// A maximal run of catch-all edges on a dirty min-cost path: the bytes
/// the transform alphabet can't explain. This localization is the
/// mining tool that found every missing rule (docs/16 §5).
#[derive(Debug, Clone)]
pub struct DirtyRun {
    pub in_off: usize,
    pub in_len: usize,
    pub out_len: usize,
}

pub enum Verdict {
    /// Every byte explained without catch-alls. `Census::diagnostics`
    /// must be zero for the explanation to be fully source-grounded.
    Reconciled(Census),
    /// Min-cost path needed catch-all edges.
    Dirty(Census, Vec<DirtyRun>),
    /// Walk abandoned (state cap); treat as refuse.
    Refused(&'static str),
}

/// What happened to one input byte, as agreed by every minimum-cost
/// parse (docs/16 §8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fate {
    /// Survives at this output offset.
    Kept(u32),
    /// Removed by the relaxation.
    Deleted,
    /// Interior byte of a re-encoded instruction (narrow/widen/
    /// longcall): no output offset is defined — only instruction
    /// starts are meaningful translation targets.
    Interior,
}

/// One input byte's verdict from the DP-intersection
/// ([`engine::translations`]): translate only `Agreed` offsets;
/// `Ambiguous` means min-cost parses disagree — refuse, never guess.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FateCell {
    Agreed(Fate),
    Ambiguous,
}
