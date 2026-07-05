# graft docs

Design notes and worklogs for graft — incremental linking for Rust.
Project name: **graft** (an overlay grafted onto a base image). See the
repo root `README.md` for what graft is and how to run it.

The docs are split in two. **Design** docs are maintained: they describe
what graft does today and are kept in sync with the code. **Worklogs**
are write-once records — dated design notes, port plans, milestone logs,
and post-mortems kept for rationale. They are not maintained and may
describe superseded specifics; read them for the *why*, not the current
contract.

## Design

- [`how-it-works.md`](./how-it-works.md) — what actually happens in the
  three link modes (base / overlay / combine) plus auto mode: the
  pre-scan, slack, the resolution-channel cascade, the walk-refusal
  fixpoint, the base-map object, the splice, and the failure philosophy.
  Start here.
- [`14-identity-granularity.md`](./14-identity-granularity.md) — the
  section-identity model: per-node `trans_hash`, positional resolution,
  why mutable content can't be content-folded. The design the resolver
  implements.
- [`16-relaxation-walk.md`](./16-relaxation-walk.md) — the xtensa
  relaxation reconciliation walk: the transform alphabet transcribed
  from binutils, needed to locate a relaxed input byte in the base.
  Reference for the in-tree `relax` engine.
- [`07-dev-environment.md`](./07-dev-environment.md) — Docker dev
  container, hardware connection, build/flash/monitor. Operational.

## Worklogs

Write-once records, not maintained. Kept for rationale.

- [`worklogs/06-graft-wrapper.md`](./worklogs/06-graft-wrapper.md) —
  original `graft` wrapper contract and `.graft.*` ELF metadata design;
  carries a reading note listing where the implementation diverged.
- [`worklogs/08-implementation-status.md`](./worklogs/08-implementation-status.md)
  — M1-era milestone log (built-vs-plan, decisions changed, numbers).
- [`worklogs/11-anon-provide.md`](./worklogs/11-anon-provide.md) —
  resolving anonymous (symbol-less) sections via per-target SHN_ABS
  symbols. Implemented; absorbed into `how-it-works.md`.
- [`worklogs/15-normal-builds.md`](./worklogs/15-normal-builds.md) —
  section-defined anchors, the base-map object, TLS map sections,
  in-template slack. PIE/dynamic parts are suspended; the ET_EXEC anchor
  and TLS-map machinery are implemented and absorbed into
  `how-it-works.md`.
- [`worklogs/13-early-trampoline.md`](./worklogs/13-early-trampoline.md)
  — design note, not implemented: what breaks if the trampoline moves
  before startup finishes.
- [`worklogs/10-mutation-experiments.md`](./worklogs/10-mutation-experiments.md)
  — closure cost / per-phase timing under small source mutations on the
  reference ESP32 firmware.
- [`worklogs/05-esp32-adaptation.md`](./worklogs/05-esp32-adaptation.md)
  — original ESP32-S3 port plan (pre-M1). Superseded in specifics by 08;
  reading note at top lists the deltas.
- [`worklogs/01-architecture.md`](./worklogs/01-architecture.md),
  [`worklogs/02-runtime-patching.md`](./worklogs/02-runtime-patching.md),
  [`worklogs/03-build-pipeline.md`](./worklogs/03-build-pipeline.md),
  [`worklogs/04-wire-protocol.md`](./worklogs/04-wire-protocol.md) —
  notes on **Dioxus's Subsecond hot-patching system**, the reference
  graft was studied against. graft resolves at link time and shares none
  of Subsecond's runtime; kept for context only.
