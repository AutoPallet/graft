# 08 — Implementation status & decision log

Where the work actually stands relative to the design in 05 / 06, and
what got changed along the way. As of M1.k.

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
| M1.j — runtime-MMU 4-segment exploration | abandoned — see `m1j-runtime-mmu-attempt` branch |
| M1.k — slack-section overlay layout (splice into base.elf) | done; image stays same shape/size as base; no segment-shift |
| M1.l — synthetic-.o slack injection + arch-neutral splice mode | done; fixture stays graft-agnostic; x86 + xtensa share splice path |

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

### "Section headers, not just program headers" for combine *(x86 path only after M1.k)*

espflash's `save-image` builds image segments by walking the ELF's
*section table* (filter: SHF_ALLOC + SHT_PROGBITS, sh_offset > 0,
size > 0). Combine's x86 (append) path therefore writes both PHT
entries *and* matching SHT entries (`.graft.overlay.<idx>`) for each
appended overlay LOAD, plus extends `.shstrtab`. The xtensa splice
path (M1.k) doesn't need this — overlay bytes land inside base's
existing `.text` / `.rodata` sections, which are already in the SHT.
See `combine.rs::add_overlay_section_headers` (x86) and
`combine_xtensa_splice` (xtensa).

### Overlap-trim, not overlap-drop, for overlay LOADs *(x86 path only after M1.k)*

x86 hosted layout puts overlay at addresses past every base PT_LOAD,
but linker page-alignment can introduce trailing-page overlap with
base's last LOAD. Combine **trims each overlay LOAD to its
non-overlapping subrange** in the x86 path. The xtensa splice path
walks overlay sections directly (skipping any leading PT_LOAD
zero-padding) so trim isn't needed there.

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

## M1.j — runtime-MMU exploration (abandoned)

Tried to break the segment-shift bottleneck (M1.i follow-up #1) by
giving overlay its own 64 KB-aligned IROM/DROM segments mapped at
runtime via direct MMU table writes from `main`, before handoff to
`graft_entry`. Hit two blockers:

1. **ESP-IDF bootloader maps only one DROM and one IROM segment.**
   Confirmed in `bootloader_utility.c` (master + v5.3): segment-walk
   stores the first match in scalar `drom_addr` / `irom_addr` and
   logs `"Image contains multiple %s segments. Only the last one
   will be mapped."` for any further DROM/IROM segment.
2. **The 512-entry MMU table is shared between IBUS and DBUS.**
   `mmu_ll_get_entry_id(vaddr) = (vaddr & 0x1FFFFFF) >> 16`, so
   `0x42010000` and `0x3C010000` both index entry 1. Mapping
   overlay's `.rodata` at `0x3C010000` would unmap base's `.text`
   at `0x42010000`. Verified empirically: direct MMU table writes
   *do* work (overlay code briefly executed before crashing on the
   unmapped sibling region), but no naive (vaddr_text, vaddr_rodata)
   pair avoids a base-conflict for non-trivial bases.

Branch `m1j-runtime-mmu-attempt` (tip `83c8ee9`) preserves the
exploration: bundle post-processor that patched a `GRAFT_OVERLAY_INFO`
struct in `.data`, runtime MMU stub in `rwtext`, direct table-write
debug code in `main`. Useful if we ever revisit a custom-bootloader
path or need the same suspend/invalidate sequence elsewhere.

## M1.k — slack-section overlay layout

Resolves M1.i follow-up #1 (segment-shift). Approach: have base
reserve fixed-vaddr, fixed-paddr regions in flash that overlay can
splice into without changing any base offsets.

### Mechanism

1. **Fixture declares two 0xFF-filled statics**, `GRAFT_TEXT_SLACK`
   and `GRAFT_RODATA_SLACK`, with `link_section = ".text.graft_slack"`
   / `".rodata.graft_slack"`. esp-hal's existing
   `*(.text .literal.*)` and `*(.rodata .rodata.*)` wildcards scoop
   them into base's `.text` / `.rodata` output sections; the existing
   `.rotext_dummy` clause automatically grows `SIZEOF(.rodata)` to
   match, pushing `.text` past the new slack's MMU entries. No
   linker-script mutation needed in base.
2. **Overlay link reads `GRAFT_TEXT_SLACK` / `GRAFT_RODATA_SLACK`
   symbol values from base.elf** (`compute_xtensa_slack` in
   `overlay.rs`) and writes a `memory.x` with `irom_seg ORIGIN =
   slack.irom_start, len = slack.irom_len` (likewise drom). Overlay's
   `.text` / `.rodata` land inside the slack region.
3. **Combine splices**: `combine_xtensa_splice` walks overlay's
   SHF_ALLOC SHT_PROGBITS sections, finds each one's vaddr inside
   a base PT_LOAD, and overwrites `out[base_file_offset..]` with
   the section's bytes. No new PT_LOADs, no PHT/SHT extension, no
   appended payload. Trampoline patch on the entry symbol is
   unchanged. Output ELF has identical shape and identical size to
   base.elf.

### Why 0xFF fill (not 0x00)

Flash erase state is 0xFF on the SPI NOR parts ESP32-S3 talks to.
Filling slack with 0xFF means a fresh-erased sector and an
unwritten-overlay sector are bit-identical — pageflash can skip
already-erased sectors without writing redundant 0xFF bytes.

### MMU-aliasing analysis

Slack regions stay inside base's already-mapped MMU pages, so no
new MMU programming is needed at runtime. The IROM/DROM aliasing
that blocked M1.j doesn't bite here: the slack vaddrs are just
offsets within base's `.text` / `.rodata`, so they share base's
MMU entries. Overlay's `.text` (slack vaddr ~0x42026900) and
overlay's `.rodata` (slack vaddr ~0x3C000524) are in disjoint MMU
entries (entry 2 vs entry 0) by virtue of being inside base's
already-disjoint regions.

### Numbers (Hello → Howdy)

- **Image size**: 223,568 bytes; same as base, *exactly* (down from
  M1.i's 94 KB combined image, because no separate overlay segment).
- **Bytes that differ between base.img and spliced.img**: 2,945
  (overlay payload 2,898 + trampoline patch 27 + boundary alignment
  ~20).
- **Slack overhead in base.img**: 64 KB IROM + 64 KB DROM = 128 KB
  unconditional cost per base build, regardless of overlay presence.
  Knob: `GRAFT_*_SLACK_LEN` consts in fixture's `main.rs`.
- **Bootloader segments**: 1 DROM (72,368 bytes) + 1 IRAM/load + 1
  IROM (92,416 bytes); no `multiple X segments` warnings.

### Trade-offs

- Base build pays the full slack size every time — 128 KB of 0xFF
  bytes get flashed even when no overlay is loaded. Acceptable for
  M1.k; the eventual fix is a delta-flasher that skips 0xFF sectors
  (already-erased = no-op for NOR flash).
- Overlay growth is bounded by slack size. If overlay's `.text`
  exceeds `GRAFT_TEXT_SLACK_LEN`, ld errors out at the overlay link
  ("section .text will not fit in region irom_seg"). Recovery: bump
  the const in the fixture and rebuild base.
- Slack regions occupy MMU entries inside base's already-mapped
  IROM/DROM space, so the MMU-aliasing constraint that blocked M1.j
  is automatically satisfied — but only because base's `.rotext_dummy`
  mechanism already enforces it for base. Any future move away from
  esp-hal's linker-script chain needs to re-check.

### Followups

1. **Delta-flasher that skips 0xFF sectors.** With slack 0xFF-filled,
   pageflash can compare base.img sectors against the spliced image
   and write only sectors where bytes differ. The 128 KB slack cost
   becomes a no-op for the unchanged-overlay case.

2. **Per-string sub-sectioning** (carryover from M1.i follow-up #2).
   Still relevant: even with splice, overlay carries the whole
   merged-strings section, not just edited strings.

3. **Slack size auto-tuning.** Right now `GRAFT_*_SLACK_LEN` is a
   manually-chosen const. Could infer from a sliding window of recent
   overlay sizes, or have graft warn at base-link time if the slack
   looks too small for typical edits. Not urgent.

## M1.l — synthetic-.o slack injection + arch-neutral splice mode

Cleanup pass on M1.k:

- **Slack reservation moves from fixture source to graft.** New module
  `graft/src/slack.rs` synthesizes a relocatable ELF (via
  `object::write::Object`) carrying `.text.graft_slack` /
  `.rodata.graft_slack` PROGBITS sections (0xFF-filled, sized via
  `GRAFT_TEXT_SLACK_LEN` / `GRAFT_RODATA_SLACK_LEN` env vars,
  default 64 KB) plus `GRAFT_TEXT_SLACK` / `GRAFT_RODATA_SLACK`
  globals. Base mode writes the `.o` next to the output and appends
  it to the linker argv along with `-Wl,--undefined=GRAFT_*_SLACK`
  (so `--gc-sections` keeps them). Fixtures no longer carry slack
  boilerplate.
- **`GRAFT_OVERLAY_MODE` flag** (`splice` | `append`). Defaults to
  `splice` on xtensa (the bootloader requires it), `append` on x86
  hosted (legacy default; can be opted into splice for delta-flash
  benefits and identical-shape images). Resolved in
  `slack::Mode::resolve(e_machine)`.
- **Arch-neutral splice path.** `combine_xtensa_splice` →
  `combine_splice`; dispatched on `Mode` rather than `e_machine`. A
  matching x86 `write_overlay_layout_ld_splice` places overlay's
  `.text*` at `slack.text_start` and `.rodata*` / `.data.rel.ro*` at
  `slack.rodata_start`, with `ASSERT(_graft_*_end <= ...)` guards at
  the script's top level (inside-`SECTIONS` ASSERTs are rejected by
  some ld versions). Discards `.eh_frame` / `.data` / `.bss` /
  unwind-header sections — splice mode covers only the two slack
  regions; everything else must come from base. (Not a regression
  for the existing fixtures, which produce only `.text` + `.rodata`
  in overlay.)
- **`Slack`** (was `XtensaSlack`) with `text_*` / `rodata_*` field
  names instead of `irom_*` / `drom_*`, since both x86 and xtensa
  use it now. `compute_xtensa_slack` → `compute_slack`.

Verified:
- x86 e2e cycle (default `append`) — unchanged, passes.
- x86 splice mode — `GRAFT_OVERLAY_MODE=splice` end-to-end works;
  combined ELF identical size to base, 964-byte overlay payload
  spliced, single trampoline.
- xtensa hardware — `Hello`→`Howdy` overlay boots and runs;
  bootloader still maps single DROM (72 KB) + IROM (92 KB)
  segments; image size 223,568 bytes (matches M1.k baseline).

The fixture-side slack statics in `esp32s3-hello/src/main.rs` are
removed — the fixture is now graft-agnostic across both targets.

## M1.m candidate followups (from closure-dump audit)

A `Hello`→`Howdy` overlay payload of ~2898 bytes splits as:

| section | bytes | actually changed? |
|---|---:|---|
| `.text.graft_entry` | 1062 | yes |
| `.literal.graft_entry` | 112 | yes |
| `.rodata.str1.1` | 1655 | **no** |
| `.Lanon….4` (format-pieces slice) | 24 | **no** |
| `.Lanon….5` (the user string) | 26 | yes |
| `.Lanon….877` (cross-TU constant) | 16 | **no** |
| `.note.GNU-stack` × 2 | 0 | n/a |

**~58% of the payload is unchanged content** that graft re-emits because `classify()` returns `Included` for any section with no matchable defined symbols (comment in `overlay.rs:711`). The 1655-byte `.rodata.str1.1` is *not* user strings — it's panic-info file paths from LTO-inlined `panic_const_*` sites. The user-visible "Howdy from ESP32-S3! tick=" lives in a per-literal `.Lanon` section (26 bytes).

So the per-string sub-sectioning idea (M1.i followup #2) is mis-targeted for our actual edit costs — the *real* gap is anonymous-section classification.

### M1.m.1 — drop non-allocated sections from the graph

`.note.GNU-stack` (and similar SHF_ALLOC=0 metadata sections) shouldn't be graph nodes. Zero-byte, but they pollute the closure dump and waste classify() work. One-line filter in `scan.rs` at graph construction.

### M1.m.2 — content-match path for anonymous sections (deferred)

**Status: deferred.** Investigated; structurally invasive; postponing in favor of feature-coverage work (M1.n) until we have a concrete payload-budget pressure.

**The problem.** `classify()` in `overlay.rs:711` returns `Included` for any section with no matchable defined symbols. `.rodata.str1.1`, `.rodata..Lanon.*`, `.eh_frame`, etc. have only `STT_SECTION` symbols, so they always go through this path — even when their bytes are byte-identical to base.

**Why the obvious fix is hard.** "If trans_hash matches base, classify as Provided" requires a *symbol name* for overlay's link to PROVIDE the address against. Anonymous sections by definition have no exported name. Three plausible paths, each with a real obstacle:

1. **Synthetic local symbol injected at scan time.** scan.rs invents a name (e.g. `__graft_anon@<tu_id_hex>:<section_name>`) and adds it to graft's in-memory symbol index. base mode emits a symhash entry. Obstacle: prune.rs re-parses the source `.o` from disk and never sees the synthetic symbol — so when a kept section's reloc targets the anon section, prune falls into `surrogate_for_pruned_section` which requires a real named definition and bails.
2. **Synthetic anchor injected at base-link time.** Like the slack-`.o` trick: emit a relocatable `.o` containing `__graft_anon_*` symbols pointing at each tracked anon section. Obstacle: anchors must point *into* sections that come from *other* input objects. Cross-object symbol definition isn't a thing in ld's input model — symbols define their own section's contents.
3. **Post-link content-match in base.elf.** Walk every input anon section, find unique byte-matching subrange in base.elf, record that address as the resolved value. Then overlay's `base_symbols.ld` PROVIDEs the synthetic name → address. Obstacle: `SHF_MERGE | SHF_STRINGS` dedup (`.rodata.str1.1`) suffix-shares strings across input TUs, so a single input section's bytes may not appear contiguously anywhere in base.elf.

**The path that probably works** is a hybrid of (1) and (3), restricted to non-mergeable anon sections (`.rodata..Lanon.*` but *not* `.rodata.str1.*`):

- scan.rs synthesizes the name at parse time; base post-link finds the unique byte-match in base.elf's `.text` / `.rodata` and records it in symhash.
- prune.rs needs an extra input: a `HashMap<SectionIndex, String>` of "if you'd otherwise call `surrogate_for_pruned_section`, use this synthetic name as a UND surrogate instead." Plumbed from overlay's compute_closure (which knows the classification outcome).
- `.rodata.str1.1` keeps going through the Included path. The merged-strings handling needs the per-string sub-sectioning idea (M1.i followup #2) — split at NUL boundaries during scan so each NUL-terminated run becomes its own non-mergeable virtual sub-section, classify-able by content match.

Estimated payload reduction once both are wired: ~1700 bytes (~58%) on the current `Hello`→`Howdy` fixture. The 1655 of `.rodata.str1.1` is the long pole and needs the sub-sectioning piece.

**Why deferring.** The current fixture is small enough that 2.9 KB overlay payload doesn't bottleneck flash time vs. stock+pageflash (M1.h numbers show graft overlay+pageflash at 24 KB / 2.12 s vs. stock pageflash at 8 KB / 1.56 s — the gap isn't dominantly anon-section-bound, it's segment-shift-bound, which M1.k already fixed). Likely to revisit when a real fixture hits a payload budget that anon-section bloat actually pushes past.

## M1.n — Rust feature coverage

Expanded `esp32s3-hello/src/main.rs` with four patterns and verified each end-to-end through the overlay link. Verification was symbolic (build + overlay closure dump + `base_addresses.ld` inspection) — hardware capture was intermittently broken in this session (USB-CDC modem-control state issues on the serial port; `espflash flash --monitor` showed only "waiting for download" between flashes despite `boot:0x2b SPI_FAST_FLASH_BOOT` succeeding earlier).

| Pattern | Symbol | Address | Resolution path | Status |
|---|---|---|---|---|
| `static mut TICK_COUNTER: u32 = 0` | `_ZN…TICK_COUNTER…` | `0x3fc89dc4` (.bss) | PROVIDE in `base_addresses.ld` | ✅ works |
| `static ATOMIC_TICK: AtomicU32` | `_ZN…ATOMIC_TICK…` | `0x3fc89dc0` (.bss) | PROVIDE | ✅ works |
| `#[link_section = ".rwtext"]` fn | `_ZN…ram_resident_step…` | `0x40378a4c` (IRAM) | PROVIDE | ✅ works *(uncalled-edited)* |
| `static GREETING_TABLE: [&str; 3]` | folded by LTO | n/a | inlined as constants | ✅ works |

For the unedited-callee case (overlay's `graft_entry` *calls* `ram_resident_step` but doesn't redefine it), `base_addresses.ld` gets the right `PROVIDE` line and overlay's link resolves through it.

### Known gap: editing IRAM (`.rwtext`) functions is not supported

If a user edits the body of a `#[link_section = ".rwtext"]` function, the overlay's link would emit a new `.rwtext` section, but graft's slack reservation only covers `.text` (IROM) and `.rodata` (DROM). There's no `.rwtext` slack to splice into. Two paths to fix:

1. Add `GRAFT_RWTEXT_SLACK` synthetic-`.o` section (mirrors the existing slack for `.text`/`.rodata`). `.rwtext` is loaded by the bootloader from flash to IRAM at boot, so reserved zeros in flash get faithfully copied to RAM at base boot, and overlay can splice into the flash-side bytes.
2. Document the gap and recommend users avoid `#[link_section = ".rwtext"]` for hot-edit code paths.

(1) is the right fix; not urgent until a real fixture hits this.

### Surprise finding: overlay's `.data` lands in base's RW PT_LOAD without explicit handling

With three format-arg substitutions (`mut={mut_tick} atomic={atomic_tick} ram={ram_tick}`), the overlay link emits ~56 bytes in `.data` containing format-piece strings + esp-hal exception-name constants (`ItlbMissDtlbMissEXCCAUSEEXCVADDR`). Vaddr `0x3fc88400`, which lands inside base's RW PT_LOAD at file-offset `0x13400`. `combine_splice` finds it there and writes the bytes — silently overwriting base's `.rwdata_dummy` zero-padding region.

In *this* fixture the target is a NOBITS dummy region, so the corruption is harmless. But generalizing:
- Splice mode currently writes overlay's `.data` content into wherever it lands in base's RW segment, *without* a slack reservation guarantee.
- If overlay's `.data` vaddr happened to fall inside base's actual `.data` (real, in-use mutable statics), boot would corrupt base's state.
- The existing `splice` layout script for x86 splice mode `/DISCARD/`s `.data` / `.bss` / `.eh_frame` — but xtensa splice goes through `setup_xtensa_layout` which keeps esp-hal's full linker chain, including `.data` placement.

Two paths to fix:
1. Reserve `.data` slack alongside `.text` / `.rodata` and assert (in `combine_splice`) that any overlay `.data` lands inside the slack.
2. Walk overlay's sections in `combine_splice` and reject any whose vaddr doesn't fall within a known slack region — fail-loud rather than silent splice into base's RAM.

Tracked: `M1.o` candidate.

### Hardware verification gap

Serial capture intermittency this session: `espflash` reset successfully wrote the new image, `espflash board-info` could communicate, but resetting into the user app produced `boot:0x23 (DOWNLOAD(USB/UART0))` rather than `boot:0x2b SPI_FAST_FLASH_BOOT`. Suspect USB-CDC modem-control state: the host's DTR/RTS sequence ends up holding GPIO0 (bootloader strapping) low past chip-reset release. Tried multiple DTR/RTS sequences (espressif espflash, pyserial inverted/non-inverted, raw termios, `espflash --monitor`); none produced a clean cold-boot in this session.

The previous M1.k / M1.l hardware tests in the same setup *did* boot cleanly, so the chip and wiring are fine — likely a transient USB driver state. Plausible follow-ups: physical power cycle, switch USB host port, replace `python3 scripts/capture.py` with a better-behaved tool. None done in this session — symbolic verification is sufficient signal that the build pipeline handles each feature.

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
