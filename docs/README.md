# Incremental Compilation Research — ESP32-S3

Research notes on Dioxus's "Subsecond" hot-patching system, and a port plan
for fast incremental edit-flash-reboot cycles on ESP32-S3.

Clone of Dioxus at `../dioxus/` (shallow, default branch) — our reference.

## Project scope

- **Target**: ESP32-S3 only (Xtensa LX7).
- **Goal**: fast edit → flash → reboot. **Not** live hot-patching.
- **Strategy**: two flash partitions (base + per-edit overlay). Overlay
  links statically against a symbol table exported from base, so all
  inter-partition calls resolve at link time to absolute flash addresses.
  No runtime jump table, no in-process patching.
- **Greenfield** — not constrained by Subsecond's u64s or existing code.

See [`05-esp32-adaptation.md`](./05-esp32-adaptation.md) for the concrete
plan.

## Reading order

1. [`01-architecture.md`](./01-architecture.md) — end-to-end mental model of
   *Dioxus's* system (reference research)
2. [`02-runtime-patching.md`](./02-runtime-patching.md) — Dioxus's runtime
   mechanism (JumpTable, `HotFn`, `call()`, `apply_patch`). **We don't use
   this** — kept for context.
3. [`03-build-pipeline.md`](./03-build-pipeline.md) — Dioxus's CLI side
   (fat → thin → undefined-symbol stubs). **We reuse the build-capture and
   symbol-parse halves.**
4. [`04-wire-protocol.md`](./04-wire-protocol.md) — Dioxus's devtools
   websocket. **We don't use this** — `esptool` + serial instead.
5. [`05-esp32-adaptation.md`](./05-esp32-adaptation.md) — **our actual
   plan**.

## TL;DR

**Dioxus's Subsecond** (docs 01-04) does in-process Rust hot-patching via a
global `AtomicPtr<JumpTable>`, an undefined-symbol stub object of
hand-assembled jump trampolines, a fat+thin build split, and a devtools
websocket carrying the table to the running app.

**Our ESP32-S3 plan** (doc 05) keeps the fat+thin *build* idea but resolves
everything at link time instead of runtime. Base partition holds all
dependencies and emits a `base_symbols.ld` (thousands of `PROVIDE(sym =
0xaddr)` entries) after its build. Overlay partition holds just the tip
crate and links with `-T base_symbols.ld` — the linker fills in every
cross-partition call via `-mlongcalls` trampolines. Flash the overlay,
reset, run. Target loop: 2-3 seconds edit-to-running.

The two-partition design is structurally a subset of hot-patching — same
address table idea, resolved earlier. Adding live patching later is
additive.

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
