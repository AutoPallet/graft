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
| M1.h — re-run churn experiments through graft | not started |

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

### M1.h — measure

Once M1.g.8 boots, re-run the M1.b churn experiments (`Hello`→`Howdy`,
+8-byte body, new function, same-size code change) through
`GRAFT=overlay`, compare pages-changed / bytes-written / wall time
against the stock-rustc M1.b numbers. Goal: 47.8 % cascading churn
drops to ~10 %.

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
