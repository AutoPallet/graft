# 08 — Implementation status & decision log

Where the work actually stands relative to the design in 05 / 06, and
what got changed along the way. As of `edcea78` (M1.g.8).

## Status snapshot

| Phase | Status |
|---|---|
| M0.25 — rustc stability probe | done |
| M0.5 — x86-64 prototype (base + overlay + combine, e2e_cycle) | done |
| M1.a–c — docker dev env, hello-world fixture, partial-flash pipeline (`pageflash.py`), churn experiments | done |
| M1.d — graft as the xtensa linker (passthrough) | done |
| M1.e — per-link telemetry | done |
| M1.f — gut M0.5 split-binary overlay; restructure for single-ELF | superseded by M1.g.0 |
| M1.g.0 — restore M0.5 implementation as starting point | done |
| M1.g.1 — single-ELF output mode (overlay's link writes the combined ELF directly) | done |
| M1.g.2 — derive overlay base address from base.elf | done |
| M1.g.3 — `arch::trampoline` boundary (xtensa skip-then-load encoder) | done |
| M1.g.4 — prune.rs accepts xtensa relocs | done |
| M1.g.5 — memory.x mutation for overlay layout | done |
| M1.g.6 — combine.rs supports ELF32 and multi-segment overlays | done |
| M1.g.7 — base mode on hardware (`.graft.manifest`/`.symhash` attached, ELF boots) | done |
| M1.g.8 — overlay mode on hardware | **done** — non-empty overlay boots and runs edited code |
| M1.h — re-run churn experiments through graft | done; **regression vs stock + pageflash** — see below |
| M1.i — drop rotext_dummy padding from overlay link | done; payload 14× smaller; full-flash 2.2× faster; pageflash now segment-shift bound |

## Key decisions changed from the 05 plan

### Destination: option B (slack at end of app partition)

The 05 doc listed five destination options as still-open. **Picked B**
because:
- No partition-table change.
- The overlay code lives in flash and is XIP-mapped through the same
  64 KB MMU page as base's `.text` (no MMU programming needed at
  runtime — the bootloader already maps the whole page for base).
- One `espflash` call handles both base and overlay (combine produces
  a single ELF; the existing `espflash flash` / `save-image` driver
  works unchanged).

The "secure-boot signing spans the partition" caveat from 05 is real
but deferred — secure boot is off in our dev fixture.

### Output shape: single combined ELF, not base + overlay pair

05 (and 06's "Overlay mode" pipeline) had base and overlay as two
separate flashable artifacts, with a runtime launcher that read an
`OverlayHeader` and jumped to overlay's entry. **Replaced with: graft
combine (now invoked internally by overlay's link) emits a single ELF
that is base.elf with overlay's sections appended at slack addresses
plus a single trampoline at base's entry symbol.** The whole pipeline
flows through stock `espflash flash` / `espflash save-image` —
nothing graft-specific runs on the device.

This makes the device-side launcher and `OverlayHeader` unnecessary
for our use case. Their absence is what makes the diff between
new.img and base.img cheap for `pageflash.py` (no wire protocol, no
manifest blob written at boot, no mutable header to invalidate).

### One trampoline only, at the entry symbol

05's "Linker minimization §6" suggested per-call-site `l32r`
literals as the long-call mechanism. **In practice we install exactly
one trampoline, at base's `entry_symbol` (typically `main`).** The
closure walk's transitive-hash cascade guarantees that any base
function whose forward-relocs reach into the closure was itself in
the closure — so by the time we're combining, no base bytes call
into overlay except via the entry handoff. The exception is `_start
→ main`, since crt-side code isn't a graft scan input. One redirect
covers it.

This is documented in `combine.rs`'s module comment.

### Layout-preserving via memory.x mutation, not custom scripts

05 had overlay supplied with its own `overlay_layout.ld`. **Now graft
keeps esp-hal's `linkall.x` / `esp32s3.x` / `hal-defaults.x` chain
unchanged and only mutates two lines in `memory.x`** — the `irom_seg`
and `drom_seg` `ORIGIN` / `len` values, so the linker bumps overlay
content into the slack region. Drop the modified `memory.x` in
graft's work_dir and prepend `-L work_dir` to ld's argv; ld's
`INCLUDE "memory.x"` resolves through the search path, work_dir wins.

esp32s3.x's `.rotext_dummy` clause forces `.text` to start at
`ALIGN(0x10000) + 0x20`, which is the (paddr % 64KB == vaddr % 64KB)
ESP-IDF cache requirement. Our slack lands wherever that alignment
puts it — usually 36–43 KB of zero padding ride along between base's
content and overlay's `.text`. We don't fight it: those bytes flash
fine and pageflash skips them since they're identical across
incremental rebuilds.

### Trampoline shape (xtensa): preserve-entry skip-then-load

05's note on `-mlongcalls` describes the per-call-site sequence rustc
emits. **Our trampoline is different — a 14-byte (then 18-byte)
skip-then-load sequence that includes a literal embedded next to the
jump, no separate literal pool.** Then we discovered Xtensa's
windowed-ABI requires base.main's `entry aN, FRAME` to be the *first*
instruction the caller's `call8` lands on. The trampoline now
preserves the original 3-byte `entry` and continues with j → l32r →
jx; jumps to overlay's `main + 3` to skip overlay's own `entry`
(which would double-allocate the frame and rotate the window). See
`arch.rs::xtensa_skip_then_load`. Constraint: overlay's frame size
must match base's (always true for "same Rust source, same
compiler"), or the windowed-ABI assumption breaks.

### "Section headers, not just program headers" for combine

espflash's `save-image` builds image segments by walking the ELF's
*section table* (filter: SHF_ALLOC + SHT_PROGBITS, sh_offset > 0,
size > 0). Combine therefore appends both PHT entries *and* matching
SHT entries (`.graft.overlay.<idx>`) for each spliced overlay LOAD,
plus extends `.shstrtab`. Without the section headers, overlay bytes
end up in the file but invisible to espflash. (For x86 Linux this
didn't matter because `mmap` walks PHT directly.) See
`combine.rs::add_overlay_section_headers`.

### Overlap-trim, not overlap-drop, for overlay LOADs

esp-hal's scripts emit dummy LOADs at base's RAM addresses
(`.rwdata_dummy`, `.vectors`) and *also* page-align flash LOADs down
to a 4 KB boundary even when the actual content sits well past that
— overlay's `.rodata` at `0x3c0019ac` lives in a LOAD with
`p_vaddr=0x3c001000`. Dropping wholesale loses overlay's literal
pool. Combine **trims each overlay LOAD to its non-overlapping
subrange** and keeps only the bytes whose vaddrs are strictly past
every base PT_LOAD. See `combine.rs::combine`'s `min_keep_vaddr`
loop.

### 4-byte slack alignment, with esp-hal's 64 KB filler

Overlay's IROM/DROM start needs to be ≤3 bytes past base's
corresponding end so espflash's `merge_adjacent_segments` (3-byte
gap tolerance) folds them into one image segment — the bootloader
errors with "Image contains multiple IROM segments. Only the last
one will be mapped" if not. compute_xtensa_slack rounds to 4-byte
alignment for that reason. The much larger gap that
`.rotext_dummy`'s `ALIGN(0x10000)+0x20` introduces lives *inside*
the merged segment as zero bytes (no separate LOAD), so it doesn't
trip the multiple-segments check.

### ELF class awareness

xtensa esp32s3 outputs ELF32; x86 host outputs ELF64. `combine.rs`
and `elf_attach.rs` are now class-aware — header offsets, phdr
layout (flags-after-memsz on ELF32), shdr size — internal Phdr
representation is canonical 64-bit-wide; truncation happens at
write. The two xtensa-only-bits in graft are the trampoline encoder
(`arch::xtensa::*`) and `setup_xtensa_layout` (memory.x mutation +
`-L work_dir` plumbing).

### What `linkall.x` we still pass through

Everything except the two memory.x lines:
- `linkall.x` itself — INCLUDE-only, unchanged.
- `alias.x` — REGION_ALIAS for ROTEXT/RWTEXT/RODATA/RWDATA. Unchanged.
- `esp32s3.x` — chip-specific SECTIONS, INSERTs. Unchanged.
- `hal-defaults.x` — `ENTRY(Reset)`, default interrupt handlers, etc.
  Unchanged. (We had to reorder `-T base_addresses.ld` *before*
  `-T linkall.x` so `__post_init`'s `PROVIDE = no_init_hook` doesn't
  fail before our PROVIDEs land.)
- `device.x`, `rwtext.x`, `rwdata.x`, `rodata.x`, `text.x`,
  `rtc_fast.x`, `rtc_slow.x`, `eh_frame.x`, `metadata.x`, `dram2.x` —
  all picked up via INCLUDE/INSERT. Unchanged.

## M1.g.8 hang — root cause and fix

**Bug:** `base.rs::build_symhash` emitted `.graft.symhash` entries only
for STB_GLOBAL/WEAK symbols, skipping every STB_LOCAL with `if
!is_global { continue; }`. Local trans_hashes were computed from the
input scan but never round-tripped through the metadata section.

**Effect:** overlay's `compute_closure` could never match a base local
on trans_hash — `symhash_by_local` was always empty. Every static and
private function in the closure got re-defined locally in overlay's
link at fresh addresses, while base kept its own copies. With LTO=fat
the closure of even a one-line edit pulls in dozens of esp-hal /
esp-println locals, so the two halves of the running program ended up
with diverged views of every shared static.

The most directly fatal one was `esp_println::LOCK` (a STB_LOCAL
`AtomicU32` initial value 0x100). base's link allocated it at
0x3fc89d1c; overlay's link re-allocated it at 0x3fc8849c. Combine then
trimmed overlay's RW PT_LOAD because it overlapped base's, so
overlay's LOCK at 0x3fc8849c was *never written to RAM at boot* and
fell inside base's `.rwdata_dummy` (an uninitialized esp-hal stack-
reservation region). At runtime, overlay's first `println!` did a CAS
against that uninitialized RAM (random power-on garbage), the CAS
never matched the expected 0x100, and the lock acquisition spun
forever — silently, with no exception or panic, since spin loops don't
fault.

**Fix:** in the post-link symhash walk, track the current
`STT_FILE` marker, derive its tu_id (same blake3-of-stt_file_name as
the input scan), and emit a SymHashEntry for every STB_LOCAL
definition with `tu = Some(tu_id)`. After the fix, overlay's
`compute_closure` correctly classifies LOCK's section as Provided,
prune.rs renames the reference to `LOCK@<tu_id_hex>` GLOBAL UND, and
`base_addresses.ld` PROVIDEs that name at base's address (0x3fc89d1c).

**Debug bisection that pinpointed it:** moved the trampoline off
`main` and onto a user-controlled `graft_entry` (via
`GRAFT_ENTRY_SYMBOL=graft_entry`). `main` then runs base's init/UART
unconditionally and dumps the trampoline + overlay-text bytes via
`read_volatile<u32>` (u8 reads from IROM cause LoadStoreError —
0x42xxxxxx is on the I-bus, only word-aligned 32-bit loads are
allowed) before the handoff. Bytes verified correct → bypassed the
trampoline by jumping to overlay's graft_entry directly via raw
address → still hung → ruled out the trampoline → started inspecting
literal-pool addresses, where the smoking gun appeared
(`_ZN…LOCK… (3fc8849c)` annotation in overlay.elf vs (3fc89d1c) in
base.elf). The tooling probe is gone from the fixture but the
trampoline-relocation pattern stayed: it's a useful loop-isolation
mode for any future bisection.

## M1.h — churn measurements

Re-ran the M1.b style churn experiments through `GRAFT=overlay` and
compared against stock-rustc + pageflash. Driver: `scripts/m1h_churn.sh`
(in-container, `--dry-run` mode for byte/page numbers; one wall-time
run on hardware for `Hello`→`Howdy` to validate).

| scenario | mode  | img_sz | pages_changed | bytes_changed |
|---|---|---:|---:|---:|
| Hello→Howdy (5↔5)        | stock | 92 KB → 92 KB  | 2 / 23 (8.7%)  | 8 KB  |
| Hello→Howdy              | graft | 92 KB → 132 KB | 16 / 33 (48%)  | 64 KB |
| Hello→Hello v2!! (+4)    | stock | 92 KB → 92 KB  | 6 / 23 (26%)   | 24 KB |
| Hello→Hello v2!!         | graft | 92 KB → 132 KB | 16 / 33 (48%)  | 64 KB |
| add new helper + call    | stock | 92 KB → 92 KB  | 3 / 23 (13%)   | 12 KB |
| add new helper + call    | graft | 92 KB → 132 KB | 16 / 33 (48%)  | 64 KB |
| `tick + 1` → `tick + 2`  | stock | 92 KB → 92 KB  | 3 / 23 (13%)   | 12 KB |
| `tick + 1` → `tick + 2`  | graft | 92 KB → 132 KB | 16 / 33 (48%)  | 64 KB |

Wall time on `Hello`→`Howdy` (chained `espflash write-bin`):

| pipeline                  | bytes | wall time |
|---|---:|---:|
| stock full-flash          | 92 KB | 2.43s     |
| **stock + pageflash**     | **8 KB** | **1.56s** |
| graft full-flash          | 132 KB | 3.28s    |
| graft overlay + pageflash | 64 KB | 2.48s    |

**Headline: graft is currently a regression vs. stock + pageflash on
this fixture.** Same shape across every scenario — graft writes a
constant ~64 KB regardless of edit size. The reason is mechanical and
fixable, not fundamental.

### Where the 64 KB comes from

The combined ELF's overlay PT_LOAD covers `0x42016b6c..0x42022543` —
~47 KB, of which:

  - **~38 KB is `.rotext_dummy` zero-padding.** esp32s3.x's
    `.rotext_dummy` clause forces `.text` to start at
    `ALIGN(0x10000) + 0x20`, the ESP-IDF cache requirement
    (`paddr % 64KB == vaddr % 64KB`). Overlay's `.text` consequently
    lands at `0x42020020`, leaving a 38 KB gap of zero bytes between
    base's IROM end and overlay's actual code.
  - **~3 KB is real overlay code/data** (graft_entry + a few
    `.rodata..Lanon.*` + the merged-strings section).
  - **~1 KB is image headers / segment metadata.**
  - **~3 KB is shifted base content** (the trampoline patch in base's
    `.text` plus a couple of pages disturbed by image-end alignment +
    the trailing SHA-256).

That zero-padding is inherent to the current single-merged-IROM-segment
strategy (which the bootloader requires, per espflash's
`merge_adjacent_segments` constraint: only one IROM/DROM segment per
image). The padding bytes are flashed because they're inside the
contiguous PROGBITS payload between base's text and overlay's text.

### What "right" looks like

For a `Hello`→`Howdy` edit, the *minimum* graft must write is roughly:

  - 1 page covering the trampoline patch in base's `.text` (~4 KB).
  - 1-2 pages covering overlay's actual `.text` + `.rodata` (~4-8 KB).
  - 1 page for SHA-256 / image-end metadata.

So a tight upper bound is 12-16 KB — already 4× better than stock
pageflash on this scenario. The 64 KB we measured is bottlenecked
entirely by the rotext_dummy padding being flashed.

**Followup work** is consolidated in the M1.i section below.

Driver script: `scripts/m1h_churn.sh`. Numbers above were collected
with `target_chip=esp32s3, espflash 4.4.0, esp-hal 1.1.0, rustc esp
fork 1.92.0.0`.

## M1.i — drop `.rotext_dummy` from overlay link

esp32s3.x's `.rotext_dummy (NOLOAD)` clause exists in base's link to
skip past the flash bytes occupied by `.rodata` so `.text` doesn't
end up reading rodata content (DROM and IROM map the same physical
flash on ESP32-S3). It rounds the skip up to `ALIGN(0x10000) + 0x20`,
costing ~38 KB of zero-padding in base's image — and, before this
fix, in every overlay rebuild's image too.

Key insight: for overlay's link, the clause is unnecessary by
construction. Overlay's `.rodata` lives in the slack DROM region
past base's DROM end; overlay's `.text` lives in the slack IROM
region past base's IROM end. The two slack regions correspond to
disjoint flash ranges, so DROM-reading-text overlap is impossible.

The cache requirement (`paddr % 64KB == vaddr % 64KB`) is satisfied
by *contiguity* with base's segment: when espflash merges base's
IROM segment with overlay's, paddr and vaddr advance in lockstep,
so any aligned-on-base position remains aligned. We just need
overlay's `.text` 4-byte slack-aligned past base's IROM end and the
merged segment is well-formed.

**Fix**: `mutate_esp32s3_x` in `overlay.rs` strips the
`.rotext_dummy` SECTIONS clause and its `INSERT BEFORE .text;` from
esp-hal's `esp32s3.x`, drops the modified copy in `work_dir`, and
relies on the existing `-L work_dir` precedence to make ld pick it
up over esp-hal's. `_rotext_reserved_start` (the only symbol the
clause defined) isn't referenced anywhere outside the clause itself
(verified by grep across all esp-hal scripts), so dropping it is
safe.

### Numbers after M1.i (Hello → Howdy)

| pipeline                  | bytes  | wall time |
|---|---:|---:|
| stock full-flash          | 92 KB  | 2.43s     |
| **stock + pageflash**     | **8 KB** | **1.56s** |
| graft full-flash          | **94 KB** (was 132) | **1.46s** (was 3.28) |
| graft overlay + pageflash | **24 KB** (was 64) | 2.12s    |

Overlay payload itself: 41,554 → **2,898 bytes** (14× smaller). The
combined image dropped from 132 KB → 94 KB. Graft full-flash now
*beats stock full-flash* outright (smaller image, faster write).

But on this particular fixture, **stock + pageflash still wins on
small edits** (8 KB vs 24 KB; ~0.6 s wall time advantage). The
remaining 24 KB graft churn breaks down as:

  - **16 KB at flash 0x10000**: base's DROM/DRAM/IRAM segments
    *shifted later in the image* because espflash placed overlay's
    `.rodata` (1.7 KB) immediately after base's `.rodata` in paddr
    order, which pushed every subsequent segment forward. So 4 pages
    of base content count as "changed" purely from being relocated
    in flash, even though the bytes themselves are identical.
  - **4 KB at 0x20000**: base's IROM page that contains the
    trampoline patch (graft's only real write into base territory).
  - **4 KB at 0x26000**: image-trailing SHA-256 / metadata page.

The dominant cost is now the *segment-shift* (16 KB / 24 KB = 67% of
the diff) — paddr layout, not real content change.

### Follow-up work after M1.i

1. **Stop shifting base segments when overlay grows.** Have
   `combine.rs` place overlay sections at *high* paddrs (past every
   base segment) rather than letting espflash interleave them by
   vaddr-sort order. The vaddr stays at the slack DROM/IROM
   addresses (the chip needs those for MMU mapping); only the file
   paddr changes. This keeps base content at its original flash
   offsets so pageflash sees only the trampoline page + overlay
   pages + checksum page diff. Estimate: ~16 KB → ~4-8 KB diff,
   crossing under stock pageflash for any non-trivial edit.

2. **Per-string sub-sectioning for `SHF_MERGE | SHF_STRINGS`.** With
   LTO=fat, all anonymous string constants land in one merged section
   (`.rodata.str1.1`, ~1.6 KB on this fixture). Editing any string
   changes the section's bytes → trans_hash differs → whole section
   in the closure. *And it's not just bloat:* base functions that
   reference strings near the changed one still resolve to base's
   copy at base's `.rodata` address, but overlay carries a duplicate
   of every string in its own `.rodata.str1.1`. GNU ld's
   `--gc-sections` doesn't drop unreferenced fragments within a
   merged section (LLD does, but Xtensa support in LLD is incomplete).

   Right fix: in `scan.rs`, recognize `SHF_MERGE | SHF_STRINGS`
   sections and split them at NUL boundaries into per-string virtual
   sub-sections, each with its own trans_hash and its own incoming
   relocs (with addend = byte offset within the original section).
   `prune.rs` and `combine.rs` would have to follow suit. Estimated
   a few hundred LOC plus careful reloc retargeting; pays off
   directly in shipped overlay bytes.

   *Possible bug if anyone ever runs graft with LLD:* base's link
   may have already dropped strings that overlay still wants to
   reference (because base's gc-sections fragmentized them out, but
   overlay's compute_closure thinks they're "Provided" by base at a
   per-section address). The current GNU-ld behavior accidentally
   masks this — every string survives in base. Worth a guard once
   we care about LLD compatibility.

3. **Closer-fit cache alignment.** Even the 4-byte-slack
   placement leaves base's IROM segment ending at an arbitrary vaddr
   and overlay's starting right after. The bootloader might map a
   final partial cache page that overflows into overlay's IROM; in
   pathological cases this could double-count the boundary page.
   Audit at implementation time.

## Things that turned out to not matter (or got simpler)

- **Per-call-site `l32r` literals.** Not needed — only one
  trampoline at the entry symbol.
- **Overlay header / launcher.** Not needed — single ELF flashes
  through espflash, bootloader hands off to base normally, base's
  entry trampoline does the rest.
- **Custom partition table.** Not needed — slack within factory
  partition.
- **MMU programming at runtime.** Not needed — overlay sits in the
  same 64 KB MMU page as base's `.text`/`.rodata`, so the bootloader's
  segment-walk maps it for free. (Even if the merged segment crosses
  one MMU page boundary, the bootloader handles that.)
- **Stacked overlays / combined-ELF snapshot tool.** Deferred until
  the basic loop works; the design composes with both, but neither
  is on the critical path.
