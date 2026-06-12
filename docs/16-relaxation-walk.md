# 16 — Relaxation reconciliation walk: everything needed for 100%

Status: knowledge dump from the `relaxwalk` prototype
(`graft/src/bin/relaxwalk.rs`, commit `37c6916`), written to enable a
clean-sheet reimplementation. The prototype hit **100.0% (9,204/9,204)**
on the roborack deploy corpus using only transforms transcribed from
binutils source. It is also ~1,400 lines of very ISA-specific code; the
goal of the rewrite is the same result with a small generic engine and
the xtensa knowledge reduced to data tables.

Everything in this document was *necessary* — each rule, encoding, and
landmine below was found by a dirty section in the corpus. Nothing here
is speculative.

## 1. Problem and role in graft

xtensa GNU ld rewrites section interiors at link time ("relaxation"):
sections shrink/grow, interior bytes move. Any graft resolution that
anchors `base_section_start + input_offset` is unsound for relaxed
sections. The fix is a *reconciliation walk*: given

- input bytes of a section (from the pristine `.o` / archive member),
- its input relocations (as field masks + literal-value sources),
- its `.xt.prop` property entries,
- the linked output bytes (from base.elf) at the section's placed
  address (start + output size recovered from the `-Map` file),

advance a cursor through both streams, explaining every byte as exactly
one transform from ld's finite vocabulary. The result is an
input-offset → output-offset translation for every surviving byte.
Anything unexplained ⇒ refuse ⇒ closure-pull/bail (never silently
wrong).

The walk is LAZY: it runs at overlay time, per anchor-target section,
only when an interior offset must be translated. Positional resolution
implies the trans_hash matched, which implies the overlay's input
object is bit-identical to base's input — so the input side is always
available. Persisted state per section stays `(base addr, output
size)`; no transform log is stored.

Ground rules (standing, from CLAUDE.md and Eric):

- **Transcribe ld's transform alphabet, never its decisions.** We
  recognize what ld did to the final bytes; we never predict what it
  would do. (Reimplementing decisions = reference-divergence trap.)
- **Ambiguity bails.** Loose matching rules are acceptable *because* a
  later DP-intersection layer only trusts a byte translation when every
  minimum-cost parse agrees; disagreement ⇒ refuse that offset. This is
  the production safety net (not yet implemented, §8).
- Bar: 100% of exec/literal relaxed sections reconciled-or-provably-
  refused on the deploy corpus. Met; the rewrite must keep it (§7).

## 2. The transform alphabet (binutils `bfd/elf32-xtensa.c`)

Source of truth: espressif/binutils-gdb tag **`esp-2.45.0_20250920`**
(what crosstool-NG esp-15.2.0_20250920 builds; this is roborack's
toolchain — *not* esp-12.2 as an earlier note claimed). Fetch:

    https://raw.githubusercontent.com/espressif/binutils-gdb/esp-2.45.0_20250920/bfd/elf32-xtensa.c

ld's action enum (`text_action_enum_t`, line ~5417) and what each does
to bytes (application loop `relax_section`, ~9880; longcall rewrite
`elf_xtensa_do_asm_simplify`, ~4711):

| action | bytes in → out | notes |
|---|---|---|
| `ta_convert_longcall` | `l32r aN; callx aN` (6) → `or a1,a1,a1; callN 0` (6) | only at `R_XTENSA_ASM_SIMPLIFY` reloc sites, pair **adjacent** (gas emits them as a unit for `-mlongcalls`; ld's `get_expanded_call_opcode` requires adjacency — non-adjacent conversion **does not exist**). The NOP is `or a1,a1,a1` = bytes `10 11 20`, *not* the canonical `nop`. The SLOT0_OP reloc moves +3 onto the call. callx window must map: callx0/4/8/12 → call0/4/8/12 (`swap_callx_for_call_opcode`; jx→j is not in the source — we allowed it, it costs nothing). |
| `ta_remove_longcall` | same → `callN 0` (3) | the convert form with the NOP then removed (internally retyped `ta_remove_insn`). |
| `ta_remove_insn` | n bytes → 0 | **only** arises from longcall NOP removal. There is NO general nop-removal or unreachable-code-deletion pass. |
| `ta_narrow_insn` | 3 → 2 | exact pair table §3, operand **values preserved** through re-encode. |
| `ta_widen_insn` | 2 → 3 | inverse table **plus** `beqz.n→beqz`, `bnez.n→bnez` (branches widen but never narrow — "may require re-expand"). Branch immediate is pc-relative (free); register pinned. |
| `ta_fill`, removed < 0 | 0 → k zero bytes | added fill is **zeros** — the copy loop's `dup_contents` is calloc'd and negative fill just bumps the cursor. Never NOPs. |
| `ta_fill`, removed ≥ 0 | k bytes → 0 | deletes existing bytes. |
| `ta_remove_literal` | 4 → 0 | dead or coalesced literal word. When section alignment > 4, a compensating `ta_fill` lands at the literal block end. |
| `ta_add_literal` | 0 → 4 | a *moved* literal (cross-pool migration); value arbitrary (reloc-carried). Corpus needed this 0 times once parsing was fixed, but it's real — keep the edge. |

Where fills happen — `ta_fill` exists only at **EBB ends**, which in
input coordinates are `.xt.prop` UNREACHABLE entries (incl. size-0
ones) or the section end. The size: `removed_bytes = extra_space - br`
where `extra_space = entry.size + align_fill(entry)` (function
`xtensa_compute_fill_extra_space`, align from the entry's ALIGN flag)
and `br = (other removals) mod section_align`. Negative ⇒ ld inserts
pad zeros because the EBB's removals missed the section alignment;
positive ⇒ deletes up to `extra_space` bytes from the entry start.
Consequences for the walk:

- every UNREACHABLE range allows: byte deletion, zero insertion,
  byte-equal advance;
- an UNREACHABLE entry with ALIGN extends to
  `align_up(start + size, 1 << pow)` — gas emits size-0 align-4
  entries for inter-function padding;
- a size-0 UNREACHABLE entry without ALIGN is still a **flex point**:
  zeros may appear there in the output with no input counterpart
  (observed: `j`; `00 00 00`; branch-target — ld removed a longcall's
  3 bytes and padded 3 back).

Multi-pass note: ld iterates relaxation to a fixpoint, but the
decisions compose into ONE monotone byte alignment — the walk
reconciles final bytes and never replays passes. No backedges in the
matching graph.

One more byte-level fact that beats all insn modeling: **ld's copy
loop is byte-oriented** (`memmove` between action offsets — it never
decodes instructions while copying). Therefore "equal bytes advance
1:1" is a legitimate, source-grounded edge. It is required in practice:
hand-written `.S` files contain padding not covered by any prop entry,
and an insn-granular walker mis-decodes across it (saw `00 00` pad +
`mov.n` widened to `or` at the next function's entry: decoder read
`00 00 0d` as one insn). Cost it above structured edges so real
transforms stay preferred; the corpus needed it for exactly 2 bytes.

## 3. Narrow/widen pair tables and encodings

`narrowable[]` (elf32-xtensa.c ~4347) and `widenable[]` (~4360):

    narrow: add→add.n  addi→addi.n  addmi→addi.n  l32i→l32i.n
            movi→movi.n  ret→ret.n  retw→retw.n  s32i→s32i.n
            or→mov.n (ONLY when the two source regs are equal)
    widen:  all of the above reversed, PLUS beqz.n→beqz, bnez.n→bnez

Operand correspondence is semantic value equality (registers and
immediates), with these field layouts — all verified against
`xtensa-esp32s3-elf-as` output (esp-15.2.0_20250920); **the bare
`xtensa-esp-elf-as` defaults to BIG-endian** — always use the
`esp32s3-` prefixed tools, and read bytes with `readelf -x` (objdump
prints insn *values*, not byte order).

Little-endian; 24-bit insn `= b0 | b1<<8 | b2<<16`; fields:
`op0 = insn & 0xF`, `t = (insn>>4)&0xF`, `s = (insn>>8)&0xF`,
`r = (insn>>12)&0xF`, `imm8 = (insn>>16)&0xFF`.
Length from byte0 low nibble: `0x0..0x7` ⇒ 3 bytes, `0x8..0xD` ⇒ 2,
`0xE/0xF` ⇒ not an instruction on esp32s3.

Wide forms:

| insn | match | operands |
|---|---|---|
| add | `insn & 0xFF000F == 0x800000` | r=dest, s, t. (Mask must cover op1 bits 16-19 — `0xF0000F` is wrong.) |
| or | `insn & 0xFF000F == 0x200000` | r=dest, s, t; mov iff s==t |
| addi | `insn & 0x00F00F == 0x00C002` | t=dest, s, imm = sext8(imm8) |
| addmi | `… == 0x00D002` | imm = sext8(imm8) × 256 |
| l32i | `… == 0x002002` | t=dest, s=base, off = imm8 × 4 |
| s32i | `… == 0x006002` | same fields |
| movi | `… == 0x00A002` | t=dest, imm = sext12(s<<8 \| imm8) — **s is immediate bits, not a register** |
| ret / retw | insn == 0x000080 / 0x000090 | — |
| beqz / bnez | byte0 == 0x16 / 0x56 | s in bits 8-11; imm12 in bits 12-23 (pcrel ⇒ free) |

Narrow forms (insn16, same field positions):

| op0 | insn | operands |
|---|---|---|
| 0x8 | l32i.n | t=dest, s=base, off = r × 4 |
| 0x9 | s32i.n | same |
| 0xA | add.n | r=dest, s, t |
| 0xB | addi.n | r=dest, s, imm = (t==0 ? −1 : t) — 0 is not encodable |
| 0xC, t bit3 = 0 | movi.n | dest = **s**; imm7 = ((t&7)<<4) \| r; value = imm7 ≥ 96 ? imm7−128 : imm7 |
| 0xC, t&0xC == 0x8 | beqz.n | s; imm6 = ((t&3)<<4) \| r (pcrel ⇒ free) |
| 0xC, t&0xC == 0xC | bnez.n | s |
| 0xD | mov.n iff r==0 (t=dest, s=src); 0xf00d=ret.n; 0xf01d=retw.n; 0xf03d=nop.n | |

Cross-pair operand mapping pitfalls: addi dest is `t`, addi.n dest is
`r`; movi dest is `t`, movi.n dest is `s`; or→mov.n maps wide `r`→
narrow `t` (dest) and wide `s`(==`t`)→narrow `s`.

When the input slot carries a reloc (mask), drop operand-value checks
but keep pair identity ("loose mode") — the relocated immediate
legitimately differs.

Other fixed encodings the walk needs:

    canonical nop   = f0 20 00      nop.n = 3d f0
    or a1,a1,a1 nop = 10 11 20      (longcall convert filler)
    l32r: op0=1, t=dest in byte0, imm16 = bytes 1-2 (pcrel ⇒ free)
    callx0/4/8/12 = byte0 c0/d0/e0/f0, byte1 = 0S, byte2 = 00; jx = a0
    call0/4/8/12: op0=5, window n = byte0 bits 4-5;  j: op0=6, n=0

Pc-relative free bits for the same-length "retarget in place" compare
(bit-granular — full-byte masks let `call8` "match" `j` or a register
change slip through):

| insn class | free bits per byte |
|---|---|
| l32r (op0=1) | `00 FF FF` |
| call (op0=5), j (op0=6 n=0) | `C0 FF FF` (offset low bits live in byte0 bits 6-7) |
| op0=6 n=1 (BRI12: beqz/bnez/bgez/bltz) | `00 F0 FF` (s pinned in byte1 low nibble) |
| op0=6 n≥2 (BRI8 imm branches, loop family) | `00 00 FF` |
| op0=7 (two-reg branches) | `00 00 FF` |
| beqz.n/bnez.n (op0=C, byte0 bit7 set) | `30 F0` |

Empirical note: in this corpus the free-bits machinery almost never
decides anything (final census `retarget: 0`) because gas emits
`R_XTENSA_SLOT0_OP` relocs on essentially every pcrel operand for
relaxation, and reloc masks subsume the free bits. Keep it anyway: it
is what makes an *unmasked* in-place retarget legal, and it tightens
what a masked compare may NOT do (opcode/register bits stay pinned).

Ground-truth bytes for unit tests (assembled, verified): see the
`#[cfg(test)]` block of the v1 prototype at commit `37c6916` —
`add 70 35 80 ↔ add.n 7a 35`, `addi(12) 32 c5 0c ↔ addi.n cb 35`,
`movi(95) 32 a0 5f ↔ movi.n 5c f3`, `movi(−32) 32 af e0 ↔ 6c 03`,
`ret 80 00 00 ↔ 0d f0`, `or(a3,a5,a5) 50 35 20 ↔ mov.n 3d 05`,
`l32i 32 25 07 ↔ l32i.n 38 75`, `s32i 32 65 07 ↔ s32i.n 39 75`,
`beqz 16 e5 02 ↔ beqz.n 9c 45`, `bnez 56 b5 02 ↔ bnez.n dc 25`,
`l32r 31 ee ff`, `callx8 e0 03 00`, `call8 65 fb ff`, `j c6 eb ff`,
`jx a0 03 00`. Port these tests verbatim — they catch every field-layout
mistake made along the way.

## 4. Input-side extraction (where most failures actually were)

**Reloc masks.** A reloc of reported size 0 (`R_XTENSA_SLOT0_OP`,
`R_XTENSA_ASM_EXPAND`) masks the *instruction slot* at its offset —
use `insn_len(byte0)` (2 or 3), not a fixed 3, or a SLOT0_OP on a
density insn bleeds into the next one. Size-N relocs mask N/8 bytes.

**`.xt.prop`** is the per-region truth: 12-byte records
`(address, size, flags)`, one `R_XTENSA_32` reloc on each address
field whose target *section symbol* says which section the entry
describes (match by physical section index — names are not unique).

> **Landmine (cost a full debugging round, capped the corpus at ~90%):**
> gas stores the entry's in-section offset in the **field bytes** with
> a zero RELA addend. Other emitters use the addend with zero field.
> Read `field + addend`. Reading addend-only silently makes every
> range start at 0; the walk still "works" but census churn explodes
> (lit-del/lit-add pairs) and ~10% of sections go dirty.

Flag bits (include/elf/xtensa.h): LITERAL 0x1, INSN 0x2, DATA 0x4,
UNREACHABLE 0x8, loop-target 0x10, branch-target 0x20, no-density
0x40, no-reorder 0x80, NO_TRANSFORM 0x100, bt-align 0x600, ALIGN
0x800, alignment-pow `(flags>>12)&0x1F`, abslit 0x20000.

Classification that sufficed for 100%:

- `LITERAL` ⇒ literal range (word-wise matching, §5);
- `UNREACHABLE` ⇒ flex region: extend end to ALIGN boundary when ALIGN
  set; record `start` as a flex point **always, even at size 0**;
- neither INSN nor LITERAL nor UNREACHABLE ⇒ data range (raw bytes,
  byte-equal/masked only, no transforms) — jump tables in gcc text;
- loop/branch-target/no-density/no-transform/bt-align: decision inputs
  only, no byte effect — ignored.

`.literal.*` sections are one whole literal range (they have no prop
entries of their own).

**Literal word values.** The decisive fix for literal regions: a word
with an `R_XTENSA_32` reloc against a *named* symbol that has a
*unique* address in the linked image has a knowable output value
`addr(sym) + addend` — match it **by value**. (At overlay time the
linked image is base.elf, always in hand.) Without this, dead literal
words — reloc-masked, so "match anything" — eat output code
positionally: the corpus case was a 7-word pool at the *front* of
`.text.esp_wifi_connect` where two longcall conversions later in the
function killed their pool words; masked-match-any consumed the first
8 bytes of output code instead. Build the name→address table once from
the output ELF, dropping names with multiple distinct addresses;
section-symbol-targeted words stay masked (residual ambiguity that
DP-intersection must cover).

**Archive members.** esp-idf archives contain *duplicate member
names* (`libmbedcrypto.a` has two `bignum.c.obj`: generic + esp32s3
hardware-MPI port; same for `esp_efuse_utility.c.obj`,
`efuse_hal.c.obj`). The map names members by string only — collect all
name matches and disambiguate by (section name, section size); bail
if still ambiguous (2 sections in the corpus). Production graft knows
exact member offsets from its own scan, so this is a prototype-only
concern.

**Map side.** Only relaxed entries matter: an input-section line whose
following line ends `"(size before relaxing)"`. Gives
`(in_name, out_addr, out_size, in_size, obj_spec)`. Long names wrap
onto their own line. Non-exec relaxed entries are SHF_MERGE string
folding (different mechanism, graft v7 territory) — excluded, 2,917 in
the corpus.

## 5. Walk architecture that reached 100%

Per section, a shortest-path search over states `(i, o)` (input
offset, output offset), edges generated by region:

- **literal range** (word granularity): match word — by expected value
  if known, else masked⇒any, else byte-equal — cost 0; delete word
  cost 1; insert word cost 2 (dearer so delete/insert drift pairs
  don't tie with honest parses); zero-byte insert at edges cost 1
  (the compensating fill when section align > 4).
- **unreachable range**: byte-equal/masked advance 0; delete input
  byte 0; insert output zero 0.
- **data range**: byte-equal/masked advance 0 only.
- **code**: in priority order —
  1. **longcall first** — the l32r slot is fully reloc-masked, so a
     masked same-length compare would eat l32r-vs-anything and orphan
     the callx (this ordering bug cost a debugging round in v1);
     match `l32r aN; callx aN` → `callN` (cost 1) or
     `or a1,a1,a1; callN` (cost 1), checking l32r.t == callx.s and the
     call window;
  2. same-length verbatim/retarget: bytes equal ∨ input-masked ∨
     diff ⊆ free bits — cost 0;
  3. narrow (cost 1), widen (cost 1) via exact pair tables;
  4. flex-point zero insertion (cost 1) when `i` is an unreachable
     entry start;
  5. byte-granular verbatim (equal ∨ masked, advance 1:1) — cost 2;
  6. catch-alls: replace (i+1,o+1) cost 12, skip-input cost 16,
     skip-output cost 16 — these never produce "reconciled"; a
     min-cost path that uses them yields a **Dirty** verdict whose
     replaced-byte runs localize what the alphabet can't explain
     (Eric's weighted-search idea; it is the mining tool that found
     every missing rule).
- tails: input remainder ⇒ EBB-end fill deletion; output remainder
  must be zeros ⇒ fill.

Verdicts: `Reconciled(action census)` (no catch-alls on the min path),
`Dirty(replaced runs)`, `Refused(reason)`. Diagnostic-only edges
(output nop insertion / input nop deletion, cost 6) exist to *measure*
whether any real case needs a non-source rule — final corpus: **zero**
uses; the 92.3% plateau of v2 had been quietly leaning on them.

The prototype kept a greedy single-pass fast path with Dijkstra
fallback; this is an optimization only (wall time is ~95% archive
re-reading, not search — cache parsed members keyed by archive path
in the rewrite and the greedy path is probably not worth its code).
A 3M explored-state cap never fired after the rules were complete.

## 6. Failure catalog (what each dirty pattern turned out to be)

Every entry below was a real corpus failure; the clean sheet should
expect to reproduce *none* of them if it implements §§2–5 directly.

1. **Loose structural narrow/widen** (any 3↔2 bytes) and **nop
   fill/unfill rules** in v1/v2: inflated the clean rate while hiding
   misparses; exact tables + costed diagnostics exposed the truth.
2. **"Non-adjacent longcall"** (v2 alphabet entry): an artifact of
   landmine-poisoned prop ranges, not a real ld transform. Removed.
3. **Prop offsets read addend-only** → all ranges start at 0 (§4).
   Symptom: ~90% ceiling, lit-add churn ≈ lit-del, dirty runs at small
   in-offsets inside front-of-section literal pools.
4. **Masked literal eats code**: dirty `(20,2,2)`-style runs at pool
   tail; fixed by literal value resolution (§4).
5. **Size-0 UNREACHABLE entries skipped** → the `(X,0,3)` family:
   `j; 00 00 00; <branch target>` — EBB-end pad zeros (§2 flex
   points). Most frequent residual at the 98% stage.
6. **ALIGN extension missing** → size-0 align-4 entries between
   back-to-back little functions (`cache_utils .iram1.*`): 2 pad bytes
   walked as code, `(12,1,1)` dirty runs.
7. **Insn decode across unmarked pad** (hand-written `.S`, pad not in
   any prop entry, next insn widened): byte-verbatim edge (§2 end).
8. **Duplicate archive member names** → 19 "missing section" +
   1 size-mismatch skips (§4).
9. **SLOT0_OP masks fixed at 3 bytes** over-masked density insns (§4).
10. **callx encoding wrong in v1** (only 0xc0 family; callx8 is 0xe0)
    and **longcall ordered after masked compare** — both §5/§3.

## 7. Corpus harness and acceptance criteria

Corpus (12,123 relaxed-section map annotations; 9,206 exec/literal):

- regenerate: in container `graft-rr2`, replay the captured link argv
  (`/tmp/link-argv.txt`, wrapper `/tmp/capture-linker.sh` — must NOT
  be named `*-ld` or rustc flips linker flavor) adding
  `-Wl,-Map=/workspaces/roborack/target/corpus.map`;
- linked ELF: `~/roborack2/target/xtensa-esp32s3-espidf/vehicle/deps/deploy-2a131fb3ee41be93`;
- run from
  `~/roborack2/target/xtensa-esp32s3-espidf/vehicle/build/esp-idf-sys-b8b4dafca91fe4cc/out/build`
  (map archive paths are relative to it) with
  `--path-map /workspaces/roborack=/home/eric/roborack2`.

A reimplementation is accepted when, on this exact corpus:

- attempted = 9,204; reconciled = 9,204 (100.0%);
- skips: 2,917 merge-fold (non-exec), 2 ambiguous-member bails;
- zero uses of any non-source rule on reconciled paths;
- action census in the ballpark of: verbatim 178,058 · longcall 11,016
  · longcall-convert 156 · narrow 3,277 · widen 6,201 · fill-zero 813
  · unreachable-deleted 310 · lit-del words 38,839 · lit-add 0 ·
  byte-verbatim 2;
- the §3 ground-truth encoding tests pass.

(Exact census equality isn't required — equal-cost parse ties can
shift attribution — but order-of-magnitude deviations mean a rule is
doing the wrong work.)

## 8. Not yet built (next after the rewrite)

- **DP-intersection ambiguity detection** — the production safety
  net: enumerate *all* minimum-cost parses (forward×backward DP over
  the same edge set); a byte offset is translatable only if every
  surviving parse maps it identically; else that offset (not the whole
  section) is refused. This is what makes loose rules safe.
- **CI oracle**: symbol-saturate a fixture object (nameless locals
  every few bytes), link, harvest ld's st_value movements as ground
  truth for the walk's translations; plus fuzzing with random
  `-mlongcalls` C (reconcile-or-refuse, never misalign).
- **Wiring into resolve** as the lazy interior-translation path with
  three modes: verify-identity (sizes equal ⇒ degenerate walk =
  byte-compare modulo reloc fields — also upgrades x86 positional
  resolution from trusted to verified), transform-walk, refuse ⇒
  pull/bail.

## 9. Notes for the clean sheet

What is irreducibly xtensa (target trait material, mostly *data*):
insn length from byte0; the two pair tables with field-correspondence
descriptors; longcall site shape + the `or a1,a1,a1` filler; free-bit
masks; nop encodings; `.xt.prop` flag semantics. Everything else —
map parsing, member loading, region model (literal/flex/data/code),
the weighted search, verdicts, census — is target-independent engine.
The v1 prototype interleaved them; the rewrite shouldn't.

Plausible size reductions observed from the prototype: drop the greedy
fast path (search is not the bottleneck; archive IO is — cache parsed
members instead); generate all edges from one region-dispatched table
instead of two hand-written walkers; express pair tables as const data
(`(wide match mask/value, narrow op0/discriminant, operand field map)`)
rather than two enums and a match ladder; the Dirty/replaced-run
reporting can live entirely in path reconstruction.
