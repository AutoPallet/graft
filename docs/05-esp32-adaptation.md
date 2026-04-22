# 05 — Port plan: ESP32-S3 incremental flash

## Scope

- **Target**: ESP32-S3 only (Xtensa LX7, `xtensa-esp32s3-none-elf`).
- **Goal**: fast edit → rebuild → deliver → reboot → running code. Not live
  hot-patching. A reset between edits is fine.
- **Shape**: two-region split — a large stable **base** plus a small
  per-edit **overlay**. Overlay is the transitive closure of callers of
  every function whose content-hash changed. Membership is computed at
  function granularity, not at crate or codegen-unit granularity.
- **Overlay destination is left open.** Flash partition, slack at the end
  of the app partition, or SRAM are all viable. The rest of the design is
  parametric on this choice — only the delivery/handoff code changes.
- **Greenfield.** Addresses are `u32`, no constraint to be
  wire-compatible with Subsecond's `u64` jump table.

## What "incremental" buys us

1. `rustc` incremental codegen — only modified CUs get re-emitted.
2. Link only the closure (minutes → seconds, especially given
   `xtensa-esp-elf-ld` is slow).
3. Deliver only the overlay bytes (KB, not MB).
4. Skip partition tables, OTA negotiation, bootloader A/B.

Target loop: **1-3 seconds** edit-to-running, mostly bounded by delivery
time. SRAM delivery would be the fastest path (no flash write), flash-slack
delivery is the most operationally simple.

## The overlay region

Abstract it. Base needs three parameters:

- `OVERLAY_ENTRY` — the address to jump to.
- `OVERLAY_SRC` — where to read overlay bytes from on boot, if copying is
  needed (may be "nowhere, already XIP'd from flash").
- `OVERLAY_DEST` — where execution actually happens.

The overlay is linked against `OVERLAY_DEST`. If delivery requires a copy,
base performs it before the handoff.

### Destination options

| Option | `OVERLAY_DEST` | Delivery | Persists reset | Pros | Cons |
|---|---|---|---|---|---|
| A: dedicated flash partition | XIP (`0x422xxxxx`) | `esptool write_flash` to that partition | yes | clean, OTA-shaped, explicit partition entry | partition table change; size committed up front |
| B: slack at end of app partition | XIP (`0x422xxxxx`) inside the app partition | `esptool write_flash` past base's length | yes | zero partition-table change | base must never grow into the slack; secure-boot signing spans the partition so would have to be off or per-segment |
| C: SRAM, flash-backed | SRAM (`0x40380000` instruction bus / `0x3FC90000` data bus) | write to flash partition, base copies to SRAM on boot | yes | fast execution once loaded, no XIP cache pressure | eats ~N KB of internal SRAM; copy at boot adds ms |
| D: SRAM, host-pushed | SRAM as above | UART/USB-JTAG push from dev host at every boot | no | fastest dev loop — no flash writes, no wear | base has to idle waiting for push; requires host presence |
| E: PSRAM | PSRAM-mapped instruction window | flash partition → copy to PSRAM, or direct XIP from PSRAM | depends | big (MB) | slower than SRAM; PSRAM code execution has caveats; board must have PSRAM |

Defer picking one to M1. The rest of this document stays
destination-agnostic.

## Base and overlay roles

### Base

- ESP-IDF 2nd-stage bootloader + startup.
- All dependency code (`esp-hal`, `esp-wifi`, allocator, logger, panic
  handler).
- Any tip-crate function that is **not** in the current change closure.
- A launcher run after ESP-IDF init: reads `OverlayHeader` (from flash,
  SRAM, or wherever `OVERLAY_DEST` is), optionally copies bytes from
  `OVERLAY_SRC`, zeroes overlay BSS, copies overlay `.data`, jumps to
  `OVERLAY_ENTRY`.
- Build artifact: a section-level reverse-relocation graph + per-symbol
  content-hash map, cached for reuse by every subsequent overlay build.

### Overlay

- Every function (and every data object) in the current change closure.
- Includes its own copy of `main` — always, since `main` is the
  closure's root. Base's `main` is effectively dead code after the
  launcher jumps away.
- An `OverlayHeader` at a fixed offset (offset 0 of the overlay region is
  simplest).

### Handoff

```rust
#[repr(C)]
pub struct OverlayHeader {
    pub magic: u32,                                    // 0xEC37_1A00
    pub abi_version: u32,                              // base ABI hash
    pub entry: unsafe extern "C" fn() -> !,
    pub bss_start: *mut u8, pub bss_end: *mut u8,
    pub data_load: *const u8,                          // source in flash/elsewhere
    pub data_start: *mut u8, pub data_end: *mut u8,
}

pub fn launch_overlay() -> ! {
    const HDR_DATA_VIEW: *const OverlayHeader = OVERLAY_DEST_DATA_ADDR as _;
    unsafe {
        // Optionally: copy bytes from OVERLAY_SRC to OVERLAY_DEST first.
        // Skipped if OVERLAY_DEST is XIP'd from flash.
        let h = &*HDR_DATA_VIEW;
        assert_eq!(h.magic, OVERLAY_MAGIC);
        assert_eq!(h.abi_version, BASE_ABI_VERSION);
        core::ptr::write_bytes(h.bss_start, 0,
            h.bss_end.offset_from(h.bss_start) as usize);
        core::ptr::copy_nonoverlapping(h.data_load, h.data_start,
            h.data_end.offset_from(h.data_start) as usize);
        (h.entry)()
    }
}
```

`BASE_ABI_VERSION` is a hash over base's exported symbol signatures (see
below). If base is rebuilt and any signature shifts, overlays built
against the old base refuse to boot.

## Determining overlay membership

Three steps: hash, graph, closure.

### 1. Per-section content hashing

For every section in every object file (base's `.rcgu.o`s cached from its
build, plus overlay-candidate objects this build):

- **Content hash** of a section = `blake3(section_bytes || sorted_relocs)`
  where `sorted_relocs` is a canonical encoding of each relocation as
  `(target_symbol_name, offset, reloc_type, addend)`. Symbolic — stable
  across rustc versions and CGU repartitioning.

Per-section only. No transitive hash, no SCC handling — the closure
walk in step 3 propagates changes transitively via recursion, so we
don't need to precompute it.

Properties:

- Whitespace or reformatting edits that don't affect codegen produce
  identical hashes — no cascade.
- Across-branch caching works: switching branches back and forth
  converges on the same hashes, zero overlay.
- Strictly more precise than rustc's incremental fingerprints, which can
  be conservative across compiler upgrades and CGU boundary shifts.

### 2. Forward-relocation graph

Each section's relocation records — as they come out of ELF parsing,
uninverted — are the call graph. For section `S`, `forward_relocs(S)` is
the list of `(target_symbol, offset, reloc_type, addend)` tuples emitted
by the compiler for that section. That's the raw data we already have;
no separate graph construction step.

This captures:

- **Direct calls** — call instruction emits a code-section relocation
  against the callee.
- **Address-taken, stored in rodata** — static function tables, const
  `fn` arrays. The rodata section has a relocation to the function.
- **Vtables for `dyn Trait`** — compiled as rodata constants with one
  relocation per entry.
- **FFI callback registration** — address production requires a
  relocation at the site passing the pointer.
- **Closures** — the closure's captured fn-pointer field is populated via
  a relocation somewhere in the constructing function.

The only hole is inline assembly that computes absolute addresses
arithmetically with no relocation (`movi a8, 0x42001234; callx8 a8`).
Document as a constraint: base must not do that. If it must (e.g.
bootloader-style low-level code), mark the affected sections as "always
live" in a sidecar allowlist.

### 3. Closure computation

Walk forward from `main` with a memoized per-section "needs overlay?"
predicate:

```
def needs_overlay(s):
    if s in memo: return memo[s]
    result = (content_hash(s) != cached[s.name]) or \
             any(needs_overlay(reloc.target) for reloc in forward_relocs(s))
    memo[s] = result
    return result

needs_overlay(main)    # populates memo for everything reachable from main
closure = {s for s, v in memo.items() if v}
```

Why walk down rather than up from a diff set:

- Natural anchoring — unreachable changes don't bloat the overlay.
- Uses the forward-reloc graph as it comes out of ELF, no inversion.
- O(V+E) with memoization; whole no-change subtrees cost one `False`
  propagation.
- Trivially parallelizable on independent callees.

Post-pass for sections dropped from base at link time (COMDAT dedup, ICF,
weak resolution, anything the linker pruned even with `--no-gc-sections`):

```
changed = True
while changed:
    changed = False
    for s in closure:
        for reloc in forward_relocs(s):
            t = reloc.target
            if t.section in closure: continue        # internal to overlay
            if t in base_symbols: continue           # PROVIDE covers it
            closure.add(t.section)                   # dropped; pull it in
            changed = True
```

The added sections are resolved the same way as primary closure members
— bytes + relocations carried into the overlay. Since we work at
section granularity (`-ffunction-sections -fdata-sections`), pulling in
a dropped symbol adds only its own section, not the enclosing .rcgu.o.

### 4. Overlay assembly

Closure is materialized by reading each section's bytes + relocations
from its source `.rcgu.o`, emitting a single consolidated input object,
and handing that to `ld` alongside `-T overlay_layout.ld` and the
minimal `base_symbols.ld`. Standard ELF surgery via the `object` crate —
no persistent fallback archive, no pre-LTO caching, no custom resolution
logic. Every section the overlay needs is present as either (a) a local
definition in the consolidated object or (b) a PROVIDE'd address in the
script.

Properties:

- If a pure leaf edit: the closure is just that one function, plus every
  caller up to `main`. Overlay is tiny.
- If a base-crate function is edited: the closure still includes only
  what transitively reaches that function. No rebuild of base.
- If `main` itself is edited: closure = `{main}`. Minimum case.

## Linker minimization

Xtensa's `ld` is the slowest step of the tooling — minimize its work:

1. **Hand `ld` exactly the closure.** A single consolidated input object
   containing only closure sections, not every rlib with
   `--gc-sections`. Linker's job shrinks to "relocate N sections into
   overlay layout."
2. **Emit a minimal `base_symbols.ld`.** Only PROVIDE entries for the
   specific base symbols the overlay's relocations target. Typical case
   is 100-500 entries, not thousands.
3. **Turn off `--gc-sections` on the overlay link.** We've already done
   the GC ourselves, more precisely. The linker shouldn't re-walk
   relocations.
4. **LTO discouraged in base.** Correctness is preserved — content-hash
   diff is robust to cross-module inlining, since any byte change picks
   up via the walk — but LTO re-runs from scratch on every base rebuild
   and its non-local inlining heuristics can balloon closure sizes
   unpredictably on small edits. Cargo's default (`lto = false`) is the
   good dev-loop setting.
5. **Cache base's per-section content hashes + symbol-address table**
   once per base build. Re-parsing `base.elf` + all `.rcgu.o`s on every
   overlay build would dwarf the link time.
6. **Pre-resolve literals we know.** Every `l32r` literal addressing a
   base symbol has a known value from `base_symbols.ld` — we can write
   those bytes ourselves and hand `ld` pre-resolved input, skipping one
   relocation pass.

If `ld` is still the bottleneck after all that, **replace it for the
overlay link**. The operations left are: concatenate closure section
bytes, apply relocations (all target addresses known), lay out per the
overlay script, emit an ELF. Xtensa's active relocation types in Rust
output are a small set (`R_XTENSA_32`, `R_XTENSA_SLOT0_OP`,
`R_XTENSA_ASM_EXPAND`, `R_XTENSA_DIFF32` and a few variants). ~500 lines
of Rust with the `object` crate handles it. Only worth building if we
measure `ld` as a significant fraction of the loop time — M3 decision.

## Build pipeline

`dx-esp` is a **linker shim**, nothing else. Cargo drives the build;
rustc produces the object files; our shim intercepts the final link and
is where all the real work happens. Mode is selected via a `DX_ESP`
environment variable: `base`, `overlay`, or unset (passthrough).

`.cargo/config.toml`:

```toml
[target.xtensa-esp32s3-none-elf]
linker = "dx-esp"
rustflags = [
    "-C", "link-arg=-mlongcalls",
    "-C", "link-arg=-ffunction-sections",
    "-C", "link-arg=-fdata-sections",
    "-C", "link-arg=-Wl,--no-gc-sections",
    "-C", "link-arg=-T",  "-C", "link-arg=layout.ld",
]
```

### Base build (`DX_ESP=base cargo build`)

1. Cargo resolves deps, invokes rustc as usual. Every crate compiles
   with `-ffunction-sections -fdata-sections -mlongcalls`.
2. Final bin: rustc invokes `dx-esp` (via `linker = "dx-esp"`) with the
   complete link command.
3. Shim in `base` mode:
   - Parse all input `.rcgu.o`s: per-section content hashes +
     `(symbol_name → defining_section)` index + per-section forward
     relocations. Write to `target/dx-esp/base-graph.bin`.
   - Run the real linker (`xtensa-esp-elf-ld`) against all inputs to
     produce `base.elf` at `-o`'s path.
   - Read base.elf's final symbol table → `target/dx-esp/base-syms.bin`
     (the authoritative address map for `base_symbols.ld` generation).
   - Compute `BASE_ABI_VERSION` from exported signature hashes.
   - Convert to `base.bin` via `esptool elf2image`.
4. Flash bootloader + partition table + `base.bin` once (or whenever
   base changes).

### Overlay build (`DX_ESP=overlay cargo build`)

1. Cargo's fingerprint walk detects what changed and re-invokes rustc
   for those crates — rustc's own incremental handles within-crate
   selectivity. Any unchanged crate is skipped entirely by cargo.
2. If anything was rebuilt, cargo invokes `dx-esp` for the final link
   with the complete command (all `.rcgu.o`s + all transitive rlibs,
   resolved paths, correct order).
3. Shim in `overlay` mode:
   - Parse the link command to get the full input set (all `.rcgu.o`s
     and rlibs for this build).
   - Load cached `base-graph.bin` and `base-syms.bin`.
   - Compute content hashes for every section in the current input set.
   - Walk forward from `main`, memoized: `needs_overlay(s)` = section
     changed OR any forward-reloc target needs overlay. Closure = memo's
     truthy set.
   - Post-pass: for any closure reloc targeting a symbol not in base's
     symbol table (dropped at link time), add that symbol's section to
     the closure. Iterate to fixed point.
   - Emit minimal `base_symbols.ld` — PROVIDE entries for every symbol
     targeted by a closure reloc that isn't in the closure itself.
   - Assemble one consolidated input object: concatenate closure section
     bytes, carry their relocations (rewritten to be internally
     consistent).
   - Invoke `ld` with: `-T overlay_layout.ld`, the generated minimal
     `base_symbols.ld`, `-nostdlib`, and the consolidated object as the
     sole input. Output: `overlay.elf`.
   - Write an `OverlayHeader` into the image (a
     `#[link_section = ".overlay_header"] #[no_mangle] static` in
     whichever closure-resident crate owns it, or a post-link patcher).
   - Package per destination: `esptool elf2image` for flash-backed, raw
     binary for SRAM-copied.
   - Emit a machine-readable metadata line on stdout
     (`{"status":"linked","overlay":"…","size":…,"abi":"…"}`) for the
     dev driver.
   - Write a stub ELF at `-o`'s path so cargo is satisfied with the
     link output. The real artifact lives at the side-channel path.
4. If cargo skipped the link (no inputs changed), the shim isn't
   invoked — dev driver sees no metadata, skips flashing.

### Delivery loop

Simple orchestration on top of `cargo build`:

```
notify-watch workspace
on change:
    run `DX_ESP=overlay cargo build --target xtensa-esp32s3-none-elf`
    if shim emitted {status:linked}:
        deliver overlay per destination:
            A/B: esptool write_flash <addr> overlay.bin → reset
            C:   esptool write_flash <flash_src> overlay.bin → reset
            D:   open USB-JTAG, wait for base-ready, push bytes
        stream serial
    else:
        (nothing changed — skip)
```

No rustc wrapper, no per-crate arg capture, no replay. Cargo's
fingerprint walk (~50-200 ms on a small workspace) is cheap enough.
Cargo's own invalidation handles Cargo.toml / feature / toolchain
changes automatically — a rebuild that needs to rebuild base (because
deps graph shifted) just invokes the linker with `DX_ESP=base` and
proceeds.
- Destination D: open a USB-JTAG/UART session, wait for base to reach its
  "ready for overlay" prompt, push bytes, have base jump. No flash
  write.

## ESP32-S3 and Xtensa specifics

Most of this plan is generic ELF/object work. A short enumeration of
what isn't, tagged by scope:

### ISA-level (Xtensa, one flag)

**`-mlongcalls` is non-negotiable.** `call8` is PC-relative ±512 KB;
overlay-to-base distances routinely exceed this and base-internal calls
might too once `-ffunction-sections` scatters functions. `-mlongcalls`
makes the compiler emit:

```
l32r   a8, .L_literal   ; 3 bytes, reads abs addr from literal pool
callx8 a8               ; 3 bytes, indirect call
.L_literal: .word symbol ; 4 bytes, R_XTENSA_32 — resolved by linker
```

at every call site. No separate trampoline; the sequence is inline. 5
bytes and ~1 cycle overhead vs. a direct `call8`. This is the ISA floor —
there is no longer-reach direct call instruction on Xtensa.

Analogues on other ISAs if we ever target them: ARM `-mlong-calls`,
AArch64 `-mcmodel=large`, RISC-V `-mcmodel=medany`, x86-64 needs nothing
(`call rel32` already reaches ±2 GB).

### ISA-level (bookkeeping, not implementation)

**Literal pools are per-image.** Overlay literals live in overlay's
`.literal`; base's in base's. Cross-image calls resolve via linker-
written literals — our `base_symbols.ld` PROVIDEs feed the
`R_XTENSA_32` relocation on the overlay's literal word. We don't touch
literal pool layout; `ld` handles it.

**Windowed ABI.** Shared across images by construction — same rustc,
same toolchain, same target. No ABI friction at the boundary.

### ESP-family-level (all ESP chips, not just S3)

- `esptool elf2image` + `esptool write_flash` for delivery.
- Partition-table format and ESP-IDF 2nd-stage bootloader conventions.
- ESP-IDF startup hook where our launcher runs after `app_main`.
- `#[ram]` / `.iram0.text` section conventions for code that runs with
  the instruction cache disabled. Base keeps IRAM-resident code; overlay
  should not need IRAM placement in normal dev. If it does, extend
  `OverlayHeader` with an IRAM `(load_src, dest_start, dest_end)` triple
  and have the launcher copy.

### SoC-level (ESP32-S3 specifically)

- XIP instruction window base: `0x4200_0000`.
- XIP data window base: `0x3C00_0000`.
- Flash layout offsets.
- IRAM/DRAM address ranges if we use option C (SRAM, flash-backed).

### Generalization footprint

Extracting the ISA/ESP-family/SoC knobs into a small `TargetProfile`
struct would let the same `dx-esp` binary support ESP32-C3/C6 (RISC-V)
and other microcontrollers with ELF outputs. Not on the path for v1,
but the locked-in surface area is narrow — a handful of constants and
one compiler flag.

## What we reuse from Dioxus

| Piece | Reuse? |
|---|---|
| `cli/link.rs` — linker shim structure and `NoLink`-style arg capture | Yes; adapted for our modes. |
| ELF symbol/section parsing from `HotpatchModuleCache::new` | As input to reverse-reloc graph + content-hash computation. |
| `notify`-based file watcher from `serve/` | Yes. |

## What we don't need

| Piece | Why not |
|---|---|
| `rustcwrapper.rs` + per-crate JSON args capture | Cargo drives rustc; we don't need to know what rustc ran with. |
| `WorkspaceRustcArgs` replay + topo sort | Cargo does it. |
| "Cold-cache" fallback detection (Cargo.toml watch, etc.) | Cargo self-invalidates. |
| `subsecond` runtime crate, `JumpTable`, `apply_patch`, `HotFn` | Nothing patches in-process. |
| Undefined-symbol stub assembler | `ld` resolves from PROVIDE entries. |
| ASLR anchor | No ASLR on bare metal. |
| `catch_unwind` / `HotFnPanic` | No live patching. `panic = "abort"`. |
| Devtools websocket | `esptool` or a serial pipe. |
| Rustc incremental `.rcgu` metadata as a change signal | Replaced by transitive content hashes. |
| Crate-granularity overlay | Replaced by section-granularity closure. |

## Design constraints

- **No hand-rolled absolute jumps in base.** Any runtime-computed
  indirect call (e.g. in the bootloader) must come with a symbol-table
  allowlist entry, or the reverse-reloc graph will miss its target.
- **Base ABI stability** is enforced by `BASE_ABI_VERSION`. Any change
  to an exported signature bumps the version; overlays built against
  an older base refuse to boot. This is a loud failure, not a subtle
  crash.
- **Closure size budget**. Sanity-check at overlay build time. A closure
  that blows the region budget indicates either a structurally-central
  edit (e.g. to a type pervasive in the workspace — typically forces a
  base rebuild) or a missing GC (bug in our closure analysis).
- **Genuinely new dependencies** (tip crate imports a crate base
  doesn't have) → rebuild base. Detectable by checking the closure for
  sections we don't have any objects for.
- **Struct layout changes in base** will produce content-hash changes
  at every consumer, auto-expanding the closure to include them. No
  special handling needed; just watch the closure size.

## Future: hot-patching on top of this

The closure approach generalizes directly. A hot-patch is the overlay,
delivered without a reset, installed by redirecting base's indirect calls
(through the `l32r` literals that already exist) to the new overlay
addresses. The literals become a de-facto jump table — already
write-accessible from base since they live in `.rodata` or a writable
`.literal` section we nominate.

Not on the critical path, but the present design is compatible with that
future.

## Future: stacked overlays

Instead of replacing the overlay on each edit, *append* a new one to the
same region. Overlay N can resolve symbols from base ∪ overlay[0..N-1],
newest-definition-wins. Each edit is strictly smaller — we only emit the
sections that changed since the *most recently live* version of them,
not since base.

Shape:

- Overlay region becomes a bump arena with a persisted write cursor
  (small sidecar in flash, or the tail of the region itself).
- Per-overlay manifest kept alongside the bytes: `(section_name,
  content_hash, final_address)` triples. On boot, the launcher walks
  manifests newest-first and builds the effective symbol table in RAM,
  then indirects through it if we have a jump table — or via the
  `l32r` literals already written if we want linked-in resolution.
- `base_symbols.ld` generation stacks: when building overlay N, the
  shim loads base's cache *plus* every prior overlay's manifest, with
  newer entries shadowing older ones. Closure walk compares each
  section's content hash to whatever version is currently live (base's
  or the newest overlay's), not just base's.
- When the region fills, compact by rebuilding base from source — the
  shadow chain collapses back to an empty stack.

Interactions:

- **Destination.** Nudges firmly toward option A (dedicated partition
  with a bump cursor) or B (slack at end of app partition). C/D stay
  viable for single-shot overlays but don't benefit from stacking.
- **Closure size.** Typical edit changes the same tip function
  repeatedly during development; stacked mode means each repeat costs
  only the diff from the previous overlay, not from base. In practice
  expect 2-10× smaller per edit than non-stacked for tight iteration.
- **Literal-pool resolution** still works unchanged — each overlay's
  `l32r` literals point at whatever address the shadow chain resolved
  at its link time. Older literals keep pointing at older versions,
  which is correct: those call sites are themselves shadowed.
- **Debuggability cost.** A given symbol now lives at whichever address
  the newest defining overlay put it at; tooling that reads a single
  ELF breaks. Fix is a combined-ELF dump produced from base + manifest
  stack on demand, not continuously.

Not on the critical path. The M2 closure machinery composes with this
directly — the only new work is manifest persistence and the
newest-first shadow walk during `base_symbols.ld` generation.

## Milestones

### M0 — baseline (1 day)

Plain ESP32-S3 Rust project, one partition, `cargo run`. Measure full
edit→running time. Record the "before."

### M0.5 — x86-64 Linux prototype (~1 week)

Validate the core mechanism on native hardware before fighting any
embedded-specific quirks. Most of the plan is generic ELF work, so this
exercises the interesting parts with a fast iteration loop.

Shape:

- Two-crate workspace: `base/` (launcher) and `app/` (user code =
  overlay contents).
- Base built with `relocation-model=static` (non-PIE) so its symbols
  have fixed link-time addresses. System ASLR left alone globally.
- Base launcher:
  - Reads `./overlay.bin`.
  - `mmap(MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE)` at a high
    fixed address (e.g. `0x5_0000_0000`) — well clear of executable,
    heap, and default mmap placements.
  - Copies bytes in, `mprotect` R+X, validates header, calls
    `header.entry`.
- Overlay linked at the mmap address via a small linker script; header
  at offset 0.
- `dx-esp` shim in base + overlay modes: emits content hashes, computes
  closure, consolidates sections, invokes `ld`.

Deliverables:

- Edit `app/src/main.rs` → `DX_ESP=overlay cargo build` rewrites
  `overlay.bin` → re-run base → new code executes.
- Instrument shim to print closure members. Characterize closure sizes
  on representative edits (leaf edit, mid-graph edit, top-of-graph
  edit). Compare overlay size to full-app size.
- Validate that resolved symbols go to the right place: base symbols
  resolve via `base_symbols.ld`, overlay-internal resolve locally. Make
  sure returning-from-overlay-into-base works for standard library
  calls.

What it does not exercise: `-mlongcalls`, esptool, partition tables,
ESP-IDF startup, reboot cycles, XIP mapping. Those all come back at M1.

Faithfulness to the embedded model: non-PIE base + `MAP_FIXED` means
`base_symbols.ld` has identical format across prototype and embedded —
absolute addresses chosen by the linker. No ASLR-rebasing pass, no
runtime fixups.

### M1 — two-region boot, hard split (3-5 days)

Pick a destination (probably A or B). Hand-split the project into base
and overlay crates, manually. Base launcher reads overlay header and
jumps. Both partitions rebuilt from scratch every time. No closure
analysis yet.

Deliverable: "hello world from overlay" with the handoff proven.

### M2 — content-hash + forward-reloc + closure (1 week)

- Base shim caches pre-link per-section content hashes and
  `(symbol → defining_section)` index; post-link caches the final
  symbol→address table.
- Implement the memoized `needs_overlay` walk from `main` over forward
  relocations.
- Implement the dropped-symbols fixed-point post-pass.
- Replace the manual split with the automatic one.
- `-ffunction-sections -fdata-sections` on both builds.

Deliverable: editing one tip-crate function produces an overlay
containing only that function's closure up to `main`.

### M3 — `dx-esp` driver (1 week)

- Implement `dx-esp` as a linker shim with `DX_ESP={base,overlay}` modes.
- Install via `.cargo/config.toml` `linker = "dx-esp"` — no
  `RUSTC_WRAPPER`.
- Base mode: real link + post-process (graph + hashes + `esptool
  elf2image`).
- Overlay mode: closure computation + minimal `base_symbols.ld` + link +
  package.
- Dev driver: `notify` watcher → `DX_ESP=overlay cargo build` → parse
  shim stdout → deliver per destination → stream serial.
- End-to-end timing. Aim: 1-3 seconds edit-to-running.

### M4 — polish

- Clear diagnostics when overlay references a removed base symbol.
- Size budgets with warnings.
- Profile `ld`; if it exceeds ~40% of loop time, replace with an
  in-driver linker.
- `BASE_ABI_VERSION` mismatch UX.
- Optional: start exploring the hot-patch extension.

## Open questions

- **Destination choice for v1.** A (dedicated partition) is the most
  operationally boring. D (SRAM, host-pushed) is the most aggressive but
  requires the host to always be present. Decide at M1 with real numbers
  on overlay size.
- **SCC content-hash canonicalization.** Need a stable
  within-SCC ordering. Mangled-name sort is the obvious choice but
  sensitive to rustc's `$` hash suffixes; we may want to strip those.
- **`-ffunction-sections` in base**: does ESP-IDF's startup code tolerate
  it? Expected yes (the GNU toolchain uses it universally), but confirm.
- **Indirect-call conservatism**: what fraction of the reverse-reloc
  graph is noise (symbols referenced by unused rodata)? Profile on a
  real project; if noisy, add an allowlist of "canonical roots" (e.g.
  `main`, ISR vectors) and walk only from those.
- **Closure stability across edits**. Want two consecutive builds with
  the same source to produce byte-identical overlays. Requires
  deterministic SCC ordering and stable section sort in the output.
- **Overlay reboot cost**. Boot time for ESP32-S3 from reset to
  `launch_overlay` is typically 100-300 ms. Dominates the loop when
  delivery is fast (destination D). Worth measuring before optimizing
  `ld`.
