# graft docs

Design notes, port plans, and post-mortems for graft — incremental
linking for Rust. Project name: **graft** (an overlay grafted onto a
base image). See the repo root `README.md` for what graft is and how to
run it.

Many of these are dated design notes or milestone logs kept for
rationale, not current reference. Each is marked below. For how it works
today, read the root README plus doc 14 (identity/resolution) and doc 16
(xtensa relaxation). Doc 15 is mostly suspended PIE/dynamic design; only
its ET_EXEC anchor and TLS-map machinery is implemented.

## Current reference

- [`14-identity-granularity.md`](./14-identity-granularity.md) — the
  section-identity model: per-node `trans_hash`, positional resolution,
  why mutable content can't be content-folded. The design the current
  resolver implements.
- [`15-normal-builds.md`](./15-normal-builds.md) — section-defined
  anchors, the base-map object, TLS map sections, in-template slack.
  PIE/dynamic parts are suspended; the ET_EXEC parts are implemented.
- [`16-relaxation-walk.md`](./16-relaxation-walk.md) — the xtensa
  relaxation reconciliation walk: the full transform alphabet
  transcribed from binutils, needed to locate a relaxed input byte in
  the base. Knowledge dump for the in-tree `relax` engine.
- [`06-graft-wrapper.md`](./06-graft-wrapper.md) — the `graft` binary's
  wrapper contract, mode-by-mode steps, and `.graft.*` ELF metadata.
  Original design; carries a reading note listing where the
  implementation diverged.

## Reference research (Dioxus Subsecond)

Docs 01–04 describe **Dioxus's Subsecond hot-patching system**, the
reference graft was studied against. graft resolves at link time and
shares none of Subsecond's runtime; these are kept for context only.

- [`01-architecture.md`](./01-architecture.md) — Subsecond end-to-end.
- [`02-runtime-patching.md`](./02-runtime-patching.md) — Subsecond's
  runtime (`JumpTable`, `HotFn`, `apply_patch`). graft does not use this.
- [`03-build-pipeline.md`](./03-build-pipeline.md) — Subsecond's CLI
  fat/thin build. graft reuses only the linker-shim + ELF-parse ideas.
- [`04-wire-protocol.md`](./04-wire-protocol.md) — Subsecond's devtools
  websocket. graft does not use this.

## Historical design notes & milestone logs

- [`05-esp32-adaptation.md`](./05-esp32-adaptation.md) — original
  ESP32-S3 port plan (pre-M1). Superseded in specifics by 08; reading
  note at top lists the deltas.
- [`07-dev-environment.md`](./07-dev-environment.md) — Docker dev
  container, hardware connection, build/flash/monitor. Operational.
- [`08-implementation-status.md`](./08-implementation-status.md) —
  M1-era milestone log (built-vs-plan, decisions changed, numbers).
  Historical; the "Current state" header at the top points to what
  shipped since.
- [`09-roborack3.md`](./09-roborack3.md) — bring-up notes for running
  graft as the base linker on a large real ESP32-S3 firmware.
- [`10-mutation-experiments.md`](./10-mutation-experiments.md) — closure
  cost / per-phase timing under small source mutations on that firmware.
- [`11-anon-provide.md`](./11-anon-provide.md) — how anonymous
  (symbol-less) sections are resolved via per-target SHN_ABS symbols.
  Implemented.
- [`12-roborack3-demo.md`](./12-roborack3-demo.md) — recipe for the
  hardware overlay-flash demo.
- [`13-early-trampoline.md`](./13-early-trampoline.md) — design note,
  not implemented: what breaks if the trampoline moves before startup
  finishes.
