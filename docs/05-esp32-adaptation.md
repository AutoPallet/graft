# 05 — Port plan: ESP32-S3 incremental flash (no hot-patching)

Revised plan. Substantially simpler than a Subsecond port because we drop
the in-process patching goal entirely.

## Scope

- **Target**: ESP32-S3 only (Xtensa LX7, `xtensa-esp32s3-none-elf`).
- **Goal**: fast edit → flash → reboot → running code. Not hot-patching.
  A reset between edits is acceptable.
- **Strategy**: two flash partitions.
  - **Base**: all dependency code + runtime. Rarely re-flashed.
  - **Overlay**: just the tip-crate code. Re-flashed per edit.
  - Overlay links against a symbol table exported from base, so all its
    references into base resolve to absolute flash addresses at *link
    time*. No runtime resolution, no jump table, no `dlopen`-equivalent.
- **Greenfield project**. No legacy `u64` addresses, no existing runtime
  to be compatible with. Design for simplicity. Addresses are `u32`.

## What "incremental" buys us

The speedup decomposes into four things:

1. `rustc` incremental codegen — only codegen units that actually changed
   get recompiled. (This is rustc's feature, not ours.)
2. Link only the overlay, not the whole app.
3. Flash only the overlay partition (~100-500 KB) instead of the whole
   app image (2-4 MB).
4. No OTA, no A/B bootloader dance — one partition write + one reset.

Target loop time: **2-3 seconds** edit-to-running, mostly flash-write
bound. For comparison a full rebuild+flash cycle today is typically
20-60 seconds on this silicon.

## Flash layout

```
0x00000000  bootloader
0x00009000  partition table
0x00010000  base.bin          (large, rarely changed — say 2 MB budget)
0x00210000  overlay.bin       (small, per-edit — say 512 KB budget)
```

XIP (execute-in-place) mapping on ESP32-S3:

- Instruction XIP window: `0x42000000` base.
- Data XIP window: `0x3C000000` base.

Same physical flash, two virtual views. We run code from the instruction
window and read overlay header/rodata via the data window.

## The two-partition model

### Base partition

Contains:

- ESP-IDF 2nd-stage bootloader and startup (`app_main` path).
- `esp-hal`, `esp-wifi`, allocator, logger, panic handler, any crate the
  overlay might want to use.
- A small launcher that runs after ESP-IDF init and hands control to the
  overlay.
- (Build artifact) a generated `base_symbols.ld` file listing every
  global symbol and its absolute address.

Base is its own `no_std` bin crate. It's completely self-contained and
will boot and idle even with no overlay flashed (useful for recovery).

### Overlay partition

Contains:

- The user's tip-crate code, compiled as a separate bin crate.
- Linked at overlay partition's XIP address (`0x42210000` for the layout
  above — `0x42000000` base + `0x210000` partition offset).
- Links in `-T base_symbols.ld` so all references to base symbols bind
  to their absolute flash addresses.
- Its own `.text`, `.rodata`, `.data`, `.bss` sections inside the
  overlay partition.
- An `OverlayHeader` struct at a known offset (offset 0 is easiest).

### Handoff protocol

```rust
#[repr(C)]
pub struct OverlayHeader {
    pub magic: u32,             // e.g. 0xEC37_1A00
    pub abi_version: u32,       // bumped when base's ABI changes
    pub entry: unsafe extern "C" fn() -> !,
    pub bss_start: *mut u8,
    pub bss_end: *mut u8,
    pub data_load: *const u8,   // source in flash
    pub data_start: *mut u8,    // dest in RAM
    pub data_end: *mut u8,
}

// Base's launcher, after ESP-IDF init is done:
pub fn launch_overlay() -> ! {
    const OVERLAY_HDR: *const OverlayHeader = 0x3C210000 as _; // data XIP view
    unsafe {
        let h = &*OVERLAY_HDR;
        assert_eq!(h.magic, OVERLAY_MAGIC, "no overlay flashed");
        assert_eq!(h.abi_version, BASE_ABI_VERSION, "overlay/base ABI mismatch");

        // zero overlay BSS
        let bss_len = h.bss_end.offset_from(h.bss_start) as usize;
        core::ptr::write_bytes(h.bss_start, 0, bss_len);

        // copy overlay .data from flash to RAM
        let data_len = h.data_end.offset_from(h.data_start) as usize;
        core::ptr::copy_nonoverlapping(h.data_load, h.data_start, data_len);

        (h.entry)()
    }
}
```

## Generating `base_symbols.ld`

After the base image is linked, a post-build step parses its ELF and
emits a linker script full of `PROVIDE` entries:

```ld
/* Auto-generated from base.elf — do not edit */
PROVIDE(_ZN6esp_hal4gpio6Output3new17h... = 0x420012a4);
PROVIDE(_ZN7esp_wifi4init17h...           = 0x42005a80);
PROVIDE(__rust_alloc                      = 0x42001130);
PROVIDE(rust_begin_unwind                 = 0x4200b7ac);
/* ... thousands more */
```

The overlay passes `-T base_symbols.ld` to the linker. Xtensa `ld`
treats these as defined symbols at those exact addresses; overlay
relocations resolve against them cleanly; no undefined symbols remain.

This is the *static* equivalent of Dioxus's `create_undefined_symbol_stub`
— same idea (satisfy missing symbols with fixed addresses) but done by
the linker instead of by us hand-assembling jump trampolines in object
files. Huge simplification.

Extraction logic reuses `HotpatchModuleCache::new` for ELF from
`dioxus/packages/cli/src/build/patch.rs:262-344`, minus the TLS handling.
Output format is the `.ld` above rather than an in-memory HashMap.

## Build pipeline

### `dx-esp build --base`

1. `cargo build` the base crate with:
   - `-C link-arg=-T base_layout.ld` — places `.text` at `0x42010000`,
     `.rodata` adjacent, RAM sections in DRAM.
   - `-C link-arg=-Wl,--no-gc-sections` — keep every symbol, since
     overlay might want any of them.
   - `-mlongcalls` — so intra-base calls also use the long-call form,
     making symbol addresses stable regardless of overlay's call
     distance (more below).
2. Post-link:
   - Parse `base.elf` → write `base_symbols.ld`.
   - Record `BASE_ABI_VERSION` (e.g. hash of the symbol table) into a
     `base_manifest.json`.
   - `esptool elf2image base.elf -o base.bin`.
3. Flash bootloader + partition table + `base.bin` once (or whenever
   base changes).

### `dx-esp build --overlay`

1. **Replay tip-crate rustc** using the command captured by the rustc
   wrapper during the base build (exactly Dioxus's mechanism — see
   `03-build-pipeline.md`).
2. Link with:
   - `-T overlay_layout.ld` (places overlay `.text` at overlay
     partition's XIP address, e.g. `0x42210000`).
   - `-T base_symbols.ld` (provides base symbol addresses).
   - `-mlongcalls` (mandatory — see next section).
   - `-nostdlib` (no libstd, no libcore reimplementation — they're in
     base).
   - Pass only the tip crate's fresh `.rcgu.o` files + any rlibs that
     are *genuinely new* (a dep the overlay added that base doesn't
     have — rare; typically forces a base rebuild).
3. Post-link: write `OverlayHeader` into the overlay ELF at offset 0
   of the overlay partition. Can be done with a pre-reserved section
   in the linker script and a Rust `#[link_section = ".overlay_header"]
   #[no_mangle] static OVERLAY_HEADER: OverlayHeader = …` declaration
   in the overlay crate.
4. `esptool elf2image overlay.elf -o overlay.bin`.

### Flash loop

1. `notify` crate sees a file change.
2. Walk workspace graph (`file_to_workspace_crate` from Dioxus). If the
   change touches a base-partition crate, mark base as stale and do a
   full rebuild + full reflash; else overlay-only.
3. Build overlay.
4. `esptool --before default-reset --after hard-reset
   write_flash 0x210000 overlay.bin`.
5. Stream serial, watch for the app's log output.

With `esptool`'s `--no-stub` flag and a persistent ROM-downloader session
you can shave the per-flash overhead further; worth investigating only
if the 2-3 second target isn't met.

## Xtensa specifics (ESP32-S3)

### `-mlongcalls` is non-negotiable

Xtensa's `call8` instruction has a ±512 KB PC-relative range. The
overlay's code lives at `0x42210000`; many base symbols live far below
`0x42200000`. The distance regularly exceeds 512 KB in both directions.

`-mlongcalls` tells the compiler to emit calls as:

```
l32r   a8, .Literal     # load 32-bit absolute address from literal pool
callx8 a8               # call via register
```

instead of direct `call8`. The `.Literal` entry can be any absolute
address — including one provided by `PROVIDE()` in `base_symbols.ld`.
This is how overlay calls into base work without any runtime fixup.

Both base and overlay should be compiled `-mlongcalls`-wide for symbol
stability.

### Literal pools

Xtensa literal-pool placement (`-mtext-section-literals` vs.
`.literal`-section-based) doesn't cross partition boundaries either
way — each partition generates its own literals. Default toolchain
behavior is fine; call it out in the `.ld` layout so overlay's
literals land in overlay partition, not dangling near base.

### Windowed ABI

Xtensa uses a register-windowed calling convention. Since both base and
overlay are compiled by the same rustc + the same toolchain, they share
the ABI. Calls across the partition boundary behave exactly like any
other function call — the ABI is not a concern.

### `#[ram]` / `.iram0.text`

Functions that must execute from RAM (flash-touching drivers, ISRs
marked with `#[ram]` in `esp-hal`) should live in **base**. Overlay
code should not need IRAM placement in normal circumstances. If an
overlay edit needs IRAM, we can extend the overlay header with an
IRAM copy block, but punt that to later.

## What we reuse from Dioxus

| Piece | Reuse? |
|---|---|
| `rustcwrapper.rs` (capture rustc args per crate) | Yes, unchanged. |
| `cli/link.rs` linker shim (capture linker args) | Yes, unchanged. |
| Workspace graph walk / change detection | Yes. |
| `HotpatchModuleCache::new` ELF symbol parsing | Yes; output format changes from HashMap to `.ld`. |
| `BuildMode` enum | Yes; redefine as `Base` / `Overlay` / `Full`. |
| `serve/` watch loop | Yes, swap websocket broadcast for `esptool` calls. |

## What we don't need

| Piece | Why not |
|---|---|
| `subsecond` runtime crate | Nothing patches in-process. |
| `JumpTable` / `apply_patch` / `HotFn` | Not applicable. |
| `subsecond::call` wrapping user code | Not applicable. |
| Undefined-symbol stub assembler | Linker's `PROVIDE()` does it. |
| ASLR anchor (`main` lookup) | No ASLR on ESP32. |
| `catch_unwind` / `HotFnPanic` | No live patching, no unwinding needed. Ship `panic = "abort"`. |
| Websocket devtools protocol | `esptool` + serial monitor. |
| Template / asset hot-reload | Out of scope for firmware. |

## Design constraints

- **Base ABI is load-bearing.** Any change to a pub signature, struct
  layout, or `#[inline]` attribute in base-partition code can change
  every caller's codegen and requires a base rebuild + full reflash.
  The `BASE_ABI_VERSION` in the manifest makes this a loud assertion
  rather than a silent crash.
- **Adding a new dep**: if the dep is new to the tip crate but already
  present in base's crate graph, overlay just references it. If the
  dep is wholly new (neither partition has it), it must be added to
  base.
- **Editing a dep**: full base rebuild.
- **Generic monomorphization**: new specializations of a base-defined
  generic instantiate in the overlay (standard rustc behavior) —
  transparently handled, as long as the generic's public contract in
  base is unchanged.
- **Overlay size budget**: we reserve ~512 KB for the overlay partition
  in the layout above. For a realistic application that's roughly
  10-20k lines of tip-crate Rust after optimization. If the overlay
  keeps growing, either bump the partition size or move code into
  base.

## Future: hot-patching on top of this

Worth naming for completeness. The two-partition design above is
structurally a subset of Dioxus-style hot-patching:

- Both resolve overlay→base references through a fixed address table.
- Ours resolves at *link* time (generate `.ld`, feed to linker).
- Dioxus resolves at *runtime* (generate jump table, apply in-process).

Adding hot-patching later is additive, not a rewrite:

1. Add a tiny subsecond-style runtime to base.
2. Change the overlay loader to copy overlay `.text` into RAM (instead
   of XIP from flash) so subsequent patches can overwrite it in place.
3. Add a UART/USB channel for streaming new overlay images without
   reset.

But until the edit-flash-boot loop feels slow, there's no reason to add
the complexity.

## Milestones

### M0 — baseline (1 day)

Plain `esp32s3` Rust project, one partition, one `cargo run`. Measure
full-cycle time. This is the "before."

### M1 — two-partition boot (3-5 days)

- Manually split the project into `base/` and `overlay/` crates.
- Write the layout `.ld` files for both partitions.
- Base launcher reads overlay header, zeros BSS, calls entry.
- Both partitions rebuilt fully every time. No symbol-table export yet.
- Prove the handoff. Get "hello world from overlay" printing.

### M2 — symbol-table export (3-4 days)

- Post-base-build step parses `base.elf` and emits `base_symbols.ld`.
- Overlay links with `-T base_symbols.ld`, `-nostdlib`.
- Verify overlay binary shrinks dramatically.
- Add `BASE_ABI_VERSION` check in the handoff.

### M3 — `dx-esp` dev driver (1 week)

- Vendor Dioxus's `rustcwrapper.rs` + `cli/link.rs`.
- Implement Base / Overlay build modes that replay tip-crate rustc.
- File watcher + workspace dep graph + dep-change → base-rebuild
  detection.
- Wire up `esptool write_flash` for overlay, `esptool write_flash` for
  base when needed.
- Stream serial output.
- Measure: hit the 2-3 second target.

### M4 — polish

- Size budget warnings.
- Nice diagnostics when overlay references a base symbol that no
  longer exists.
- Possibly: ROM-downloader session pooling in esptool for faster
  flashes.
- Possibly: overlay IRAM copy block.

## Open questions

- Is 512 KB enough overlay headroom for realistic apps? Instrument the
  first real project and adjust.
- Does `esp-hal`'s startup sequence play nicely with a second
  "application entry" distinct from `esp_idf_entry`? May need to
  intercept at a specific point in ESP-IDF init.
- How do panics propagate? If overlay panics, base's panic handler
  runs (since it's linked only into base). Good — we want that. But
  the panic info includes source locations from overlay's DWARF, which
  base doesn't know about. Probably fine, since the serial output just
  prints numbers and we decode on the host.
- Do we want to support *deliberately* running without an overlay
  (e.g. "safe mode" stub) for recovery? The launcher already handles
  this via the magic-number check; just pick a reasonable fallback
  behavior (log + sleep forever, or wait for serial command to boot
  into overlay once flashed).
