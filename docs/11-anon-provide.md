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

## Design: addend-encoded targets via one SHN_ABS symbol

We exploit two ELF facts:

1. A symbol with `st_shndx = SHN_ABS` and `st_value = V` resolves
   to the constant `V` at link time — no section, no relocation,
   just a baked-in number.
2. Most "compute final value" reloc types use `S + A` (absolute)
   or `S + A - P` (PC-relative). With `S = 0`, the result is just
   `A`, the explicit addend in the RELA record.

Combining the two: synthesize **one SHN_ABS symbol per overlay input
object** with `st_value = 0` and a fixed name (`__graft_const`).
Rewrite each Providable-anon STT_SECTION reloc to reference this
symbol with `addend = base_anon_vaddr + original_addend`. The
linker computes `0 + target = target` and writes it. No PROVIDE(),
no script changes, one extra symtab row per object regardless of
how many distinct anons we redirect.

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
   one Providable anon:
   - Append one symtab entry: `{st_shndx: SHN_ABS, st_value: 0,
     st_name: "__graft_const", st_info: STB_LOCAL|STT_NOTYPE}`.
   - For every reloc whose target is a Providable anon, rewrite
     `r_info.sym_index → __graft_const`, `r_addend → base_vaddr
     + original_addend`. Reloc type unchanged.

4. **Link.** ld processes normally. `--gc-sections` sees the reloc
   edges going to an absolute symbol (which pins no section), so
   Providable anons in overlay's input objects get pruned. Result:
   they don't ship in the overlay payload.

### Cost

- One extra symtab row per overlay input object (~24 bytes ELF64).
- O(reloc-records-touching-anons) byte rewrites in `.rela.*`
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

`objdump -d` will display thousands of relocations as
`__graft_const+0xADDR`, with the symbol name carrying no
information about which anon was meant. Functionally inert;
debugger-unfriendly.

When we want to recover debug ergonomics (e.g. addr2line landing
on a sensible name for an anon's address), the same scheme works
with a *named* SHN_ABS symbol per Providable anon — content-hash
becomes the name (`__graft_anon_<hash16>`), each reloc points at
its own symbol, and `st_value = base_vaddr` directly (addend stays
at the original value). Trades one symtab row per object for one
per Providable anon — a few thousand rows in roborack3-scale
projects, well below symtab sizes ld already handles routinely.

For now (v1): single `__graft_const` symbol. Document the per-anon
variant as a follow-up; pull the trigger on it when symbol-name
fidelity in disassembly or post-link debugger fixup becomes the
limiting factor.

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
