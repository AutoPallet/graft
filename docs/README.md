# Incremental Compilation Research — Dioxus Subsecond

Research notes on Dioxus's "Subsecond" hot-patching system, produced to inform
an adaptation for a Rust ESP32 project.

Clone of Dioxus at `../dioxus/` (shallow, default branch).

## Reading order

1. [`01-architecture.md`](./01-architecture.md) — end-to-end mental model
2. [`02-runtime-patching.md`](./02-runtime-patching.md) — how the running app
   redirects calls (JumpTable, `HotFn`, `call()`, `apply_patch`)
3. [`03-build-pipeline.md`](./03-build-pipeline.md) — how the CLI produces
   patches (fat build → thin link → undefined-symbol stubs → `.so` patch)
4. [`04-wire-protocol.md`](./04-wire-protocol.md) — how patches get from the
   CLI to the running process (websocket / devtools)
5. [`05-esp32-adaptation.md`](./05-esp32-adaptation.md) — what applies to
   ESP32, what has to change, and a concrete port plan

## TL;DR

Subsecond does **real Rust code hot-patching**, not just template/asset reload.
Three moving parts:

- **Runtime** (`subsecond` crate): a global `AtomicPtr<JumpTable>` plus a
  `HotFn` wrapper that checks the jump table on every call and trampolines to
  the new function pointer if present. Wrap your hot loop bodies in
  `subsecond::call(|| …)` and any change below that call redirects; changes
  *above* the call force an unwind (panic-and-retry) back up the stack to the
  nearest `call()`.
- **Compile** (`dioxus-cli`, aka `dx`): a "fat build" up front compiles
  everything with `--export-dynamic`, `--no-gc-sections`, and captures the
  exact rustc/linker commands for every workspace crate. On a file change, dx
  re-runs rustc for only the changed crates (replaying the captured command),
  then links the resulting object files into a small `.so`/`.dylib` *patch*
  that jumps back into the original binary's absolute addresses via a
  hand-assembled stub object.
- **Protocol** (`devtools-types`, `devtools`): a websocket carrying a
  `HotReloadMsg` containing the `JumpTable`. Client dlopen's the patch,
  rebases addresses using the `main` symbol as an ASLR anchor, and swaps the
  global `AtomicPtr<JumpTable>`.

End result: sub-second Rust edit-compile-run on desktop, mobile and web.

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
