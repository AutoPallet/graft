# graft — Incremental Compilation for ESP32-S3

Research notes on Dioxus's "Subsecond" hot-patching system, and a port plan
for fast incremental edit-flash-reboot cycles on ESP32-S3. Project name:
**graft** — overlay grafted onto base.

Clone of Dioxus at `../dioxus/` (shallow, default branch) — our reference.

## Project scope

- **Target**: ESP32-S3 only (Xtensa LX7).
- **Goal**: fast edit → rebuild → deliver → reboot → running code. **Not**
  live hot-patching.
- **Shape**: two-region split — a large stable **base** + a small per-edit
  **overlay**. Overlay membership is the transitive closure of callers of
  every function whose content-hash changed (section granularity, not
  crate granularity).
- **Overlay destination is open** — dedicated flash partition, slack at
  the end of the app partition, or SRAM (flash-backed or host-pushed) are
  all viable. Design is parametric on that choice.
- **Greenfield** — u32 addresses, no compatibility constraints with
  Subsecond or any existing runtime.

See [`05-esp32-adaptation.md`](./05-esp32-adaptation.md) for the concrete
plan.

## Status

- Workspace scaffold (`graft/`, `probes/`) in place.
- **M0.25 (rustc stability probe) — done.** Findings folded into doc 05
  & 06; `tu_id` pinned to `blake3(STT_FILE)[:8]`. Run with
  `cargo run -p rustc-stability`.
- **M0.5 (x86 prototype) — done.** Base + overlay + combine; all four
  edit scenarios pass; `e2e_cycle::full_cycle` integration test green.
- **M1 (xtensa port) — overlay loop works on hardware**, but currently
  a regression vs. stock + pageflash on flash bytes/time because of a
  ~38 KB rotext_dummy zero-padding the linker forces between base
  and overlay. Edit-to-running fixture is end-to-end correct; making
  it _faster than stock_ is the open follow-up. See
  [`08-implementation-status.md`](./08-implementation-status.md) for
  M1.h numbers and the path to fixing the padding bloat.

## Reading order

1. [`01-architecture.md`](./01-architecture.md) — end-to-end mental model of
   *Dioxus's* system (reference research)
2. [`02-runtime-patching.md`](./02-runtime-patching.md) — Dioxus's runtime
   mechanism (JumpTable, `HotFn`, `call()`, `apply_patch`). **We don't use
   this** — kept for context.
3. [`03-build-pipeline.md`](./03-build-pipeline.md) — Dioxus's CLI side
   (fat → thin → undefined-symbol stubs). **We reuse the linker-shim and
   ELF symbol-parse halves; we skip the rustc-wrapper/argv-capture half
   and let cargo drive.**
4. [`04-wire-protocol.md`](./04-wire-protocol.md) — Dioxus's devtools
   websocket. **We don't use this** — `esptool` + serial instead.
5. [`05-esp32-adaptation.md`](./05-esp32-adaptation.md) — **our actual
   plan**.
6. [`06-graft-wrapper.md`](./06-graft-wrapper.md) — detailed design of
   the `graft` binary: wrapper contract, mode-by-mode steps, `.graft.*`
   ELF metadata schema, and test harnesses.
7. [`07-dev-environment.md`](./07-dev-environment.md) — operational
   notes: Docker dev container, hardware connection, build/flash/monitor.
8. [`08-implementation-status.md`](./08-implementation-status.md) —
   what's actually built vs the plan, every decision changed along the
   way, the open hang, and what's left to measure. **Read this for
   "where are we right now."**
9. [`09-roborack3.md`](./09-roborack3.md) — bring-up notes for using
   graft as the base linker on the user's real ESP32-S3 project (vs
   the `esp32s3-hello` fixture). Container setup, `secrets.rs` stub,
   linker swap via env vars, current status.
10. [`10-mutation-experiments.md`](./10-mutation-experiments.md) —
    4×2 mutation matrix on roborack3 (site × string-vs-numeric)
    measuring closure cost + per-phase graft timing. Headline:
    introducing `log::info!` into a function that wasn't previously
    in the format-machinery closure produces a 380× cascade
    (15.6 K sections, 1.2 MB payload). Other axes are largely
    site-determined.

## TL;DR

**Dioxus's Subsecond** (docs 01-04) does in-process Rust hot-patching via a
global `AtomicPtr<JumpTable>`, an undefined-symbol stub object of
hand-assembled jump trampolines, a fat+thin build split, and a devtools
websocket carrying the table to the running app.

**graft** (doc 05) keeps the fat+thin *build* idea but resolves
everything at link time. Base is built once with
`-ffunction-sections -fdata-sections` and emits a cached per-section
content-hash table + symbol→section index + final-ELF symbol addresses.
On edit, the overlay shim walks forward from `main` with a memoized
`needs_overlay(s)` — true if `s`'s bytes changed OR any target it
forward-relocs to needs overlay. Closure = memoized truthy set. A
post-pass folds in any sections referenced but dropped from base at link
time. Overlay is linked at `OVERLAY_DEST` from a consolidated
closure-sections object + a *minimal* `base_symbols.ld` containing only
the PROVIDE entries the closure actually references. `-mlongcalls`
inlines `l32r`+`callx8` at each cross-region call site — the ISA floor,
no separate trampoline.

Target loop: **1-3 seconds** edit-to-running. The destination (flash
partition, app-partition slack, or SRAM) is left open and picked at M1.

The design is structurally a subset of hot-patching — same
address-resolution idea, done at link time instead of runtime. Adding
live patching later would reuse the closure machinery unchanged.

## Key file map (into `../dioxus/`)

| Concern | File |
|---|---|
| JumpTable definition | `packages/subsecond/subsecond-types/src/lib.rs` |
| Runtime: call, HotFn, apply_patch | `packages/subsecond/subsecond/src/lib.rs` |
| User-facing README | `packages/subsecond/README.md` |
| CLI fat/thin build modes | `packages/cli/src/build/request.rs` |
| CLI thin link / patch production | `packages/cli/src/build/link.rs` |
| Symbol diff, stub gen, JumpTable assembly | `packages/cli/src/build/patch.rs` |
| `dx` as linker shim | `packages/cli/src/cli/link.rs` |
| `dx` as rustc wrapper | `packages/cli/src/rustcwrapper.rs` |
| `dx hotpatch` subcommand | `packages/cli/src/cli/hotpatch.rs` |
| Wire protocol types | `packages/devtools-types/src/lib.rs` |
| Client apply side | `packages/devtools/src/lib.rs` |
| Hot-reload loop / file watcher | `packages/cli/src/serve/` |
