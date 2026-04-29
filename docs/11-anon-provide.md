# 11 — Providing anonymous sections

How to drop anon-section ride-along from overlay closures without
inventing per-section linker-script names.

## Problem

Sections like `.rodata..Lanon.<cgu-fp>.<n>` (rustc's anonymous rodata
for string literals, panic-location records, format-arg structs, type
descriptors, layout tables, …) carry no symbol. Code references them
via `STT_SECTION` relocations: "section index N of this object,
plus an addend."

In graft's classify pass, a section is *Provided* (resolved to base's
copy via PROVIDE in overlay's link script) only if the symhash table
contains an entry under its symbol name with a matching trans_hash.
Anons have no symbol → can't appear in symhash → can never be
Provided → always Included whenever the closure walk reaches them.

Empirical impact (roborack3 wifi-numeric, post content-stable
encoding):

- 100 sections in closure
- ~24 of those are anon entries from the wifi rcgu's pool
- many of those 24 have byte-identical content to base — they ride
  along purely because there's no name to PROVIDE against

Cf. `docs/10-mutation-experiments.md` §"Hypothesis", which ascribes
the original `fallback-string` cliff to the same pattern at 1000×
scale.

## Why STT_SECTION can't be Provided as-is

Two separate obstacles:

1. **Linker-script PROVIDE() targets symbol names**, but STT_SECTION
   relocs identify their target by section-table index, not symbol.
   The linker has nothing to look up.

2. **The natural identifier (the section name) drifts.** The CGU
   fingerprint shifts on any CGU-internal edit; the numeric suffix
   shifts when adjacent anons are added or removed. Same anon
   content can have different names build-to-build, and different
   anons can collide on names across CGU repartitionings.

So the path forward needs (a) a target representation that reaches
the linker through the symbol table and (b) an identifier robust to
name drift.

## Design: per-target SHN_ABS symbols, one per resolution target

We exploit one ELF fact: a symbol with `st_shndx = SHN_ABS` and
`st_value = V` resolves to the constant `V` at link time — no
section, no relocation, just a baked-in number.

Synthesize **one SHN_ABS symbol per unique base-resolution target**
within each pruned `.o` (`__graft_sym_<symhash>`, `st_value =
base_vaddr`). Rewrite each base-bound reloc to reference that
symbol, leaving the *original addend* unchanged. The linker
resolves references the same way it resolves any defined absolute
symbol — `S + A`, `S + A - P`, GOT-slot value `S` — so PC-relative,
absolute, AND GOT-relative relocs all work uniformly without
special handling at our end.

The symbol name is keyed on the target's symhash (16-byte content
hash) where known, falling back to a vaddr-derived key for
STT_SECTION / wrap-fallback targets that carry no symhash. Same
content across base rebuilds → same name, even if base's address
layout shifts.

### Why not a single `__graft_const + (vaddr+A)` shared anchor

The earlier v1 design used one SHN_ABS=0 symbol per pruned `.o`
with `addend = base_vaddr + original_addend`. It works for direct
relocs (PC32, ABS32, ABS64) where the linker writes `S + A`
straight into the instruction slot — `S=0`, so `A` carries the
target. It does **not** work for `R_X86_64_GOTPCREL` (and
GOTPCRELX/REX_GOTPCRELX): the linker populates the allocated GOT
slot with the symbol *value* `S` (= 0), not `S + A`, so the slot
ends up holding 0 instead of the target address. The instruction's
disp gets the addend folded in alongside the GOT-base delta,
resulting in a load from `GOT_slot + base_vaddr - 4` — almost
always an unmapped address.

Per-target symbols sidestep this: `S = base_vaddr` puts the
target's address into the GOT slot directly. Cost: a few hundred
to a few thousand extra symtab rows across the build, well below
linker scale limits.

### Pipeline

1. **Base scan, post-link.** For every anon section in base.elf,
   compute a content hash (over bytes + canonicalized reloc list).
   Record `(content_hash → vaddr)` in a side table. No mutation
   of base.elf required.

2. **Overlay scan, pre-link.** For every input `.o` containing an
   anon section:
   - Compute the same content hash.
   - If hash hits in base's table: mark the anon as Providable;
     remember the base vaddr.
   - If hash misses: anon is Included normally (ships in overlay).

3. **Reloc rewrite, pre-link.** For each input `.o` with at least
   one base-bound reloc:
   - For each unique resolution target, append one symtab entry:
     `{st_shndx: SHN_ABS, st_value: base_vaddr, st_name:
     "__graft_sym_<symhash_hex>", st_info: STB_LOCAL|STT_NOTYPE}`.
   - For every reloc whose target resolves to base, rewrite
     `r_info.sym_index → that target's __graft_sym`, leaving
     `r_addend` at its original value. Reloc type unchanged.

4. **Link.** ld processes normally. `--gc-sections` sees the reloc
   edges going to absolute symbols (which pin no section), so
   Providable anons in overlay's input objects get pruned. Result:
   they don't ship in the overlay payload.

### Cost

- One extra symtab row per *unique base-resolution target* per
  pruned `.o` (~24 bytes ELF64 each). Roborack3-scale: order
  hundreds-to-low-thousands across the whole build.
- O(reloc-records-touching-base) byte rewrites in `.rela.*`
  sections of input `.o`s. Cheap; happens during prune.
- Zero change to overlay link script, zero base.elf mutation.

## Caveats

### RELA format required

The trick depends on the addend living in the reloc record, not in
the instruction bytes. RELA gives us a full 32 (or 64) bits of
addend; REL is bounded by the instruction encoding's immediate
field and would clip arbitrary addresses.

Targets we care about: Xtensa (RELA), AArch64 (RELA), x86_64 (RELA).
i386 historically uses REL but isn't on the roadmap.

### Reloc-type bit width

Even with RELA, the reloc *type* governs how the computed value is
written. Anon references are data-pointer relocs (R_XTENSA_32,
R_X86_64_64, R_X86_64_32, R_AARCH64_ABS64) — full-word writes,
no bit-width limit beyond 32 or 64. Branch-style relocs
(R_XTENSA_SLOT0_OP, R_AARCH64_CALL26) have implicit range limits
but aren't used for anon references.

### MERGE sections out of scope

`.rodata.str1.1` and friends carry `SHF_MERGE`. The linker dedups
identical entries across input objects and reflows offsets — a
section-level `STT_SECTION + addend` reloc into a MERGE section
isn't a stable byte-offset reference at link time. Wrapping the
whole section as one Providable unit breaks merging.

Two paths if MERGE coverage matters:

- **Skip MERGE sections from this pass.** Accept that
  `.rodata.str1.1` rides along; only anon-named sections benefit.
  Lower payoff, simpler.
- **Sub-section MERGE strings.** Split at NUL boundaries during
  scan, treat each substring as its own virtual section with its
  own content hash. Higher payoff, bigger surgery — defer until
  measurements show MERGE ride-along is the dominant residual.

Current proposal: skip MERGE in v1; revisit if measurements warrant.

### Cosmetics

`objdump -d` displays each base-bound reloc as
`__graft_sym_<symhash16>+0xADDEND`. The 16-byte hex content hash
isn't a Rust mangled name, but identical content across a build
shares the same symbol so addr2line / disassembly diffs can group
references coherently.

## Validation

Replicate on x86 fixture first:

1. Add a no-op `log::info!("…")` to a function that didn't previously
   call any log machinery, in `esp32s3-hello/`-style fixture.
2. Confirm closure cliff at miniature scale (without the fix).
3. Apply the fix; closure should drop to "the function that changed
   plus its trans_hash-mismatched neighbors" — anons that match
   base by content all Provided.
4. End-to-end: overlay loads on hardware, no NVS-style address
   misresolution, no boot regression.

Then rerun the roborack3 mutation matrix
(`docs/10-mutation-experiments.md`) and look for:

- wifi-numeric: 100 → ~70 sections (drop the 24 anon ride-alongs +
  cascade tail).
- fallback-string: 15,583 → some smaller number, ideally well under
  1000. (The anon cascade is much of why this cell explodes; it
  may not collapse fully because of MERGE-string contributions
  we're punting on.)
- Other cells: cfg-numeric stays ~38 (its anons are mostly genuinely
  changed bytes, not ride-along).
