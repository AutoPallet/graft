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

### 1. Content-hash change detection

For every section in every object file (base's `.rcgu.o`s cached from its
build, plus overlay-candidate objects this build):

- **Content hash** of a section = `blake3(section_bytes || sorted_relocs)`
  where `sorted_relocs` is a canonical encoding of each relocation as
  `(target_symbol_name, offset, reloc_type, addend)`. Symbolic — stable
  across rustc versions and CGU repartitioning.
- **Transitive hash** accounts for the content hash of everything this
  section reaches through relocations. Cycles (mutual recursion) handled
  by collapsing strongly-connected components via Tarjan's, hashing each
  SCC as the sorted combination of its members' content hashes, then
  hashing SCCs in reverse-topological DAG order:

  ```
  transitive(scc) = blake3(
      scc.canonical_content_hash
      || sorted(transitive(succ) for succ in scc.successors)
  )
  ```

- **Changed set** = symbols whose transitive hash differs from the
  last-build cache.

Properties we get for free:

- Whitespace or reformatting edits that don't affect codegen produce
  identical hashes — no cascade.
- Across-branch caching works: switching branches back and forth
  converges on the same hashes, zero overlay.
- Strictly more precise than rustc's incremental fingerprints, which can
  be conservative across compiler upgrades and CGU boundary shifts.

### 2. Reverse-relocation graph

For each object file we parse, enumerate its relocation records; for each
record targeting symbol `T` from section `S`, add a reverse edge
`T ← S` to the graph.

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

- Seed = changed set from step 1.
- Walk the reverse graph upward from seed to collect every section that
  reaches a changed section. That's the "must-rebuild" set.
- Then walk **forward** from the must-rebuild set (via forward
  relocations — the original relocation edges) to collect everything
  reachable from the overlay-resident code: functions the overlay calls,
  data it references. These are the overlay's *external dependencies*,
  which split into:
  - Already present in base → referenced via `base_symbols.ld`.
  - Also in the must-rebuild set → linked into overlay directly.
- `main` is always in the must-rebuild set (seed or reached from seed;
  if seed is empty, no overlay is needed at all).

The overlay is exactly the must-rebuild set, laid out at `OVERLAY_DEST`
with relocations resolved either internally (closure-member addresses)
or externally (base symbol addresses via a minimal PROVIDE file).

Properties:

- If a pure leaf edit: the closure is just that one function, plus every
  caller up to `main`. Overlay is tiny.
- If a base-crate function is edited: the closure still includes only
  what transitively reaches that function. No rebuild of base.
- If `main` itself is edited: closure = `{main}`. Minimum case.

## Linker minimization

Xtensa's `ld` is the slowest step of the tooling — minimize its work:

1. **Pre-compute the closure.** Hand `ld` only the objects that belong in
   overlay, not every rlib with `--gc-sections`. Linker goes from
   "whole-program GC over 2MB of base" to "relocate N sections into
   overlay layout."
2. **Emit a minimal `base_symbols.ld`.** Only PROVIDE entries for the
   specific base symbols the overlay's relocations target. Typical case
   is 100-500 entries, not thousands.
3. **Turn off `--gc-sections` on the overlay link.** We've already done
   the GC ourselves, more precisely. The linker shouldn't re-walk
   relocations.
4. **No LTO in the overlay build.** ThinLTO in base is fine; overlay
   must be a straight relocatable link.
5. **Cache base's reverse-reloc graph + content-hash table** once per
   base build. Re-parsing `base.elf` on every overlay build would dwarf
   the link time.
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

### Base build (`dx-esp build --base`)

1. `cargo build` the base crate.
2. Link with:
   - `-C link-arg=-T base_layout.ld` placing `.text` at the base
     partition's XIP address, one function per section
     (`-ffunction-sections -fdata-sections`).
   - `-C link-arg=-mlongcalls` so calls to out-of-range targets use the
     `l32r`+`callx8` form. Applied to both base and overlay for call-site
     stability.
   - `-C link-arg=-Wl,--no-gc-sections`. We decide what lives — not the
     linker.
3. Post-link side effects (run once, cached for every overlay build):
   - Parse `base.elf` → per-section content hashes, reverse-reloc graph,
     symbol-address table.
   - Compute `BASE_ABI_VERSION` = hash over exported-symbol signatures.
   - `esptool elf2image base.elf -o base.bin`.
4. Flash bootloader + partition table + `base.bin`.

### Overlay build (`dx-esp build --overlay`)

1. **Replay rustc** for any crates whose source files changed, using the
   commands captured by the rustc wrapper during the base build. rustc
   incremental handles within-crate selectivity.
2. **Compute content hashes** for every section in the new object set,
   plus any base sections they reference.
3. **Diff** transitive hashes against the cached per-symbol map from the
   base build → seed set.
4. **Closure walk** over the cached reverse-reloc graph → must-rebuild
   set.
5. **External-dependency walk** → minimal `base_symbols.ld` content.
6. **Link the closure**:
   - `-T overlay_layout.ld` (`OVERLAY_DEST` address).
   - `-T base_symbols.ld` (minimal, generated this build).
   - `-mlongcalls`, `-nostdlib`, no LTO, no `--gc-sections`.
   - Inputs: just the closure's object files.
7. **Emit `OverlayHeader`** into the image (via a
   `#[link_section = ".overlay_header"] #[no_mangle] static` in whichever
   closure-resident crate wants it, or via a post-link patcher).
8. **Package** per the destination choice — `esptool elf2image` for
   flash-backed, a raw binary blob for SRAM-copied, etc.

### Delivery loop

- Destination A/B: `esptool write_flash <addr> overlay.bin` then reset.
- Destination C: `write_flash` then reset; base's launcher does the
  flash→SRAM copy.
- Destination D: open a USB-JTAG/UART session, wait for base to reach its
  "ready for overlay" prompt, push bytes, have base jump. No flash
  write.

## Xtensa specifics

### `-mlongcalls` is non-negotiable

`call8` is PC-relative ±512 KB. Overlay-to-base distances routinely
exceed this; base-internal calls might too after `-ffunction-sections`
since sections are not guaranteed contiguous.

`-mlongcalls` makes the compiler emit:

```
l32r   a8, .L_literal   ; 3 bytes, reads abs addr from literal pool
callx8 a8               ; 3 bytes, indirect call
.L_literal: .word symbol ; 4 bytes, R_XTENSA_32 — resolved by linker
```

at every call site. No separate trampoline; the sequence is inline. 5
bytes and ~1 cycle overhead vs. a direct `call8`. This is the ISA floor —
there is no longer-reach direct call instruction on Xtensa.

### Literals are per-image

Each image (base, overlay) generates its own literal pool. Overlay
literals live in overlay's `.literal` section; base literals in base's.
Cross-image calls resolve via linker-written literals (our
`base_symbols.ld` PROVIDEs feed directly into the `R_XTENSA_32`
relocation on the overlay's literal word).

### Windowed ABI

Shared across images by construction — same rustc, same toolchain, same
target. Calls cross the base/overlay boundary with zero ABI friction.

### `#[ram]` / `.iram0.text`

Anything that runs with the instruction cache disabled (flash-touching
drivers, critical ISRs) lives in base, in internal IRAM, as usual for
ESP-IDF apps. Overlay shouldn't need IRAM placement in normal
development. If it does, extend `OverlayHeader` with an IRAM
`(load_src, dest_start, dest_end)` triple and have the launcher copy.

## What we reuse from Dioxus

| Piece | Reuse? |
|---|---|
| `rustcwrapper.rs` — capture rustc args per crate | Yes, unchanged. |
| `cli/link.rs` — linker shim for arg capture | Yes, unchanged. |
| `serve/` watch loop | Yes; delivery step replaces websocket broadcast. |
| ELF symbol/section parsing from `HotpatchModuleCache::new` | As input to reverse-reloc graph + content-hash computation. |
| `BuildMode`-style dispatch | Conceptually, as `Base` / `Overlay` / `Full`. |

## What we don't need

| Piece | Why not |
|---|---|
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

## Milestones

### M0 — baseline (1 day)

Plain ESP32-S3 Rust project, one partition, `cargo run`. Measure full
edit→running time. Record the "before."

### M1 — two-region boot, hard split (3-5 days)

Pick a destination (probably A or B). Hand-split the project into base
and overlay crates, manually. Base launcher reads overlay header and
jumps. Both partitions rebuilt from scratch every time. No closure
analysis yet.

Deliverable: "hello world from overlay" with the handoff proven.

### M2 — content-hash + reverse-reloc + closure (1 week)

- Parse base's `.elf` post-build: per-section content hashes, reverse-reloc
  graph, symbol-address map — all cached to disk.
- Implement transitive-hash-with-Tarjan-SCC.
- Implement closure computation.
- Replace the manual split with an automatic one.
- `-ffunction-sections -fdata-sections` on both builds.

Deliverable: editing one tip-crate function produces an overlay
containing only that function's closure up to `main`.

### M3 — `dx-esp` driver (1 week)

- Vendor Dioxus's `rustcwrapper.rs` and `cli/link.rs`.
- File watcher, workspace graph, dep-add detection.
- Linker-minimization wiring (minimal `base_symbols.ld`, prune
  `--gc-sections`, etc.).
- Delivery step per destination choice.
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
