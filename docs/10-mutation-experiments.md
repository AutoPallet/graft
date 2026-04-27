# 10 — Mutation experiments on roborack3

A 4×2 matrix of overlay rebuilds against the user's real ESP32-S3
firmware (`~/roborack3`, fallback-only build), measuring how the
graft closure cost (and the wall-clock breakdown) responds to
small source mutations at different sites.

Goal: figure out where the overlay-payload cost is actually coming
from on a real-sized project, before building anti-cascade
machinery into graft.

## Method

For each cell:

1. `git checkout` the target file (clean state).
2. Apply a single deterministic source mutation.
3. Force a re-link by removing the deploy artifact + `touch`-ing
   the source.
4. Run `cargo bflash --no-default-features --features
   run_mode_fallback` with `GRAFT=overlay`,
   `GRAFT_BASE_ELF=/tmp/base.elf`, `GRAFT_ENTRY_SYMBOL=main`.
5. Capture graft's summary line via `GRAFT_LOG`. Record closure
   sections, payload bytes, and per-phase timing (scan, closure
   compute, prune, real-link, combine, total).
6. `git checkout` the file back.

Every cell runs against the same `/tmp/base.elf` (built with
slack overrides `GRAFT_TEXT_SLACK_LEN=2_000_000`,
`GRAFT_RODATA_SLACK_LEN=400_000`, `GRAFT_DATA_SLACK_LEN=200_000`),
so the only variable is the mutation.

Runner: [`/tmp/run_experiments.py`](#runner). Raw artifacts in
`/tmp/graft-exp-runs/` — TSV, per-cell `.graftlog` (full closure
dump), and per-cell cargo log.

### Mutation matrix

Two axes:

| Axis | Values |
|---|---|
| **site** | `fallback` (deploy entry tree), `wifi` (deploy node, depth 1), `cli` (common node, depth 1, separate crate), `cfg` (cfg crate's `dev_http`) |
| **kind** | `string` (introduces / changes a string literal); `numeric` (introduces / changes a numeric expression with no new string) |

Specific mutations:

- **fallback-string**: insert `log::info!("graft exp: …")` as the
  first stmt of `fn fallback`. fallback didn't previously call any
  log macro.
- **fallback-numeric**: insert `let _x: u32 = 1234;
  core::hint::black_box(_x);` at the same spot.
- **wifi-string**: change the existing `info!("Starting wifi…")`
  literal in `WifiNode::new`.
- **wifi-numeric**: insert `let _x: u32 = 4321;
  core::hint::black_box(_x);` in `WifiNode::new`.
- **cli-string**: insert `log::info!("…")` early in
  `CliNode::new`. CliNode doesn't currently call any log macro.
- **cli-numeric**: insert `let _x: u32 = 5555;
  core::hint::black_box(_x);` in `CliNode::new`.
- **cfg-string**: change the `format!("{} ({}) debugger", …)`
  template's `"debugger"` literal to `"debugger v2"` in
  `cfg/src/dev_http.rs`.
- **cfg-numeric**: change `let port: u16 = 80;` to `81` in the
  same file.

## Results

| Cell | Closure (sections) | Overlay payload | Pruned objs | Trampolines | Total |
|---|---:|---:|---:|---:|---:|
| **fallback-string** | **15,604** | **1,195,810 (1.2 MB)** | 405 | 1 | 6.1s |
| fallback-numeric | 41 | 28,002 (27 KB) | 4 | 1 | 3.9s |
| wifi-string | 101 | 34,450 (34 KB) | 8 | 1 | 4.0s |
| wifi-numeric | 100 | 34,450 (34 KB) | 8 | 1 | 4.0s |
| cli-string | 735 | 91,378 (89 KB) | 35 | 1 | 4.0s |
| cli-numeric | 706 | 89,518 (87 KB) | 35 | 1 | 4.1s |
| cfg-string | 38 | 39,166 (38 KB) | 4 | 1 | 4.0s |
| cfg-numeric | 38 | 39,162 (38 KB) | 4 | 1 | 4.0s |

Phase timings (graft-internal — these exclude rustc compile time):

| Cell | scan | closure | prune | link | combine |
|---|---:|---:|---:|---:|---:|
| fallback-string | 3.6s | 17.6ms | 125.7ms | **2.1s** | 75.4ms |
| fallback-numeric | 3.6s | 9.2ms | 0.6ms | 98.9ms | 72.7ms |
| wifi-string | 3.7s | 9.2ms | 3.0ms | 109.2ms | 72.2ms |
| wifi-numeric | 3.7s | 10.2ms | 3.0ms | 104.5ms | 73.6ms |
| cli-string | 3.7s | 10.3ms | 17.7ms | 157.9ms | 77.0ms |
| cli-numeric | 3.7s | 10.2ms | 17.4ms | 157.5ms | 80.7ms |
| cfg-string | 3.7s | 10.3ms | 0.7ms | 96.0ms | 75.1ms |
| cfg-numeric | 3.7s | 10.2ms | 1.9ms | 93.8ms | 77.1ms |

Compile time (rustc, before graft sees anything; mostly cached
incremental — full clean build of base was 4m20s):

| Cell | rustc | graft total | sum |
|---|---:|---:|---:|
| fallback-string | 13.6s | 6.1s | 19.7s |
| fallback-numeric | 9.9s | 3.9s | 13.8s |
| wifi-string / numeric | ~9s | 4.0s | ~13s |
| cli-string / numeric | ~15s | 4.0s | ~19s |
| cfg-string / numeric | ~12s | 4.0s | ~16s |

## Observation 1: the fallback-string cliff

**fallback-string is an outlier**: 380× the closure, 43× the
payload of any other cell. Every other (string vs. numeric) pair
is within a few percent of itself.

The cliff is about *introducing a call site for log/format
machinery into a function that didn't previously have one*. fallback
in base never called `log::info!`; the rebuilt fallback does, and
once it does, the closure walk reaches into:

- `log::__private_api::log` and the global logger
- `core::alloc::Layout::for_value_raw` — **dozens of monomorphic
  instances** (one per type printed by deeply-nested code)
- `embedded_svc::http::server::FnHandler::<F>::handle` — many
  monomorphic instances (the HTTP server's handler trait machinery)
- `embedded_io::Write` impls and friends
- `std::io::stdio::_eprint`, `std::sys::pal::unix::abort_internal`,
  panic infrastructure

Sample (excerpt from `/tmp/graft-exp-runs/fallback-string.graftlog`,
`closure sections (15604):`):

```
.literal._ZN6deploy4main…  (64 B)
.text._ZN6deploy4main…  (160 B)
.text._ZN4core5alloc6layout6Layout13for_value_raw…h0010ea5c…  (63 B)
.text._ZN4core5alloc6layout6Layout13for_value_raw…h071e7702…  (63 B)
.text._ZN4core5alloc6layout6Layout13for_value_raw…h09150603…  (63 B)
…  (≈40 distinct monomorphic instances of for_value_raw)
.text._ZN111_$LT$embedded_svc..http..server..FnHandler…h120ca383…  (1654 B)
.text._ZN111_$LT$embedded_svc..http..server..FnHandler…h5d75e31d…  (288 B)
…  (many handle() instances)
```

Each of these almost certainly *exists* in base.elf at a known
address — the question is why graft's closure walk doesn't classify
them as `Provided`.

## Observation 2: string vs. numeric is not the dominant axis

For wifi/cli/cfg the string and numeric cells produce nearly
identical numbers. The wifi pair is bit-for-bit identical at 34,450
bytes payload; cli is within 2 KB; cfg is within 4 bytes. Whatever
drives the cascade (or doesn't) is *site-determined*, not
*content-determined*, once the function in question already lives
in a closure that touches the relevant infrastructure.

This rules out the simple narrative "string mutations cascade
because string addresses change." If that were the only effect,
wifi-string would also balloon. It doesn't — because wifi already
called `info!` in base, so the format machinery's trans_hashes
were *already* anchored on that path.

## Observation 3: site depth correlates with payload, not with cascade

| Site | Depth from main | Closure | Payload |
|---|---:|---:|---:|
| fallback | 1 | 41 / 15,604 | 28 KB / 1.2 MB |
| wifi | 2 | 100 / 101 | 34 KB / 34 KB |
| cli | 2 | 706 / 735 | 89 KB / 91 KB |
| cfg | indirect (compile-time) | 38 / 38 | 39 KB / 39 KB |

Depth-1 (fallback) numeric is small (28 KB), but introducing log
infra at that depth opens a big door. Depth-2 sites (wifi/cli) sit
between 34 and 91 KB regardless of mutation kind — the closure size
is set by what the changed function *already calls* + what *its
surrounding TU* compiled to. cfg's mutation is compile-time-only
(it changes `Config::compute`'s output bytes); the closure stays
tiny because Config is mostly leaf code.

cli has a much larger floor than wifi (706 vs. 100 sections) even
though both are depth-2 single-fn edits. Most of cli's closure is
`pubsub_macros`-generated dispatch and `serde_json` / format
plumbing inside CliNode — the node's surface area is just bigger.

## Observation 4: phase timings are dominated by scan

`scan` is **~3.6 s** in every cell — graft walks 2,235 input objects
× ≈162,000 input sections every overlay rebuild, regardless of the
mutation. This is the floor cost.

The `link` phase (real linker, ld through ldproxy) varies from
~95 ms (small closure) to **2.1 s** (the fallback-string closure
of 15.6 K sections). When the closure is small, link is a tenth of
total time; when it's huge, link triples it.

`closure` (the trans_hash-driven walk) is uniformly cheap (~10 ms)
even for a 15 K-section closure — not the bottleneck.

`prune` scales with closure size (0.6 ms → 126 ms) but is also a
small fraction.

`combine` is ~75 ms in every cell — splice+append+SHT-extension is
nearly constant work.

## Hypothesis: trans_hash propagation through new-string-bearing chains

The leading theory for the fallback-string cliff: graft's
`trans_hash` includes a section's outgoing reloc list. When a kept
function in overlay references a string at a different address than
base did (because overlay's string lives at a fresh slack vaddr),
its trans_hash differs from base's — even if its byte contents are
otherwise identical. That mismatch propagates through the
recursion: every caller of the "now-different-hash" function also
mismatches, etc., all the way up.

For fallback-numeric, the mutation introduces no new string and
references no anonymous-section content. The walk stops at the
first Provided boundary near fallback itself.

For fallback-string, the new `log::info!()` references a unique
`.rodata..Lanon.*` (the format-string + module path + line number).
That section is necessarily Included (no symbol → can't be
Provided). Any function whose reloc-list includes a pointer to the
*Lanon section's address now has a different reloc list from
base's, so its trans_hash diverges. Cascade.

This is the same problem as the deferred [M1.m.2 anon-section
classify-by-content](08-implementation-status.md#m1m2--content-match-path-for-anonymous-sections-deferred):
anon sections can't be Provided because there's no symbol name to
PROVIDE against. But the *upstream effect* is dramatic — not a few
hundred bytes of unchanged content riding along, but a 380×
explosion of the closure itself.

We need to confirm this empirically before fixing.

## Next steps

1. **Confirm the hypothesis**: build a minimal fixture in
   `esp32s3-hello/` that mirrors the pattern — a function that
   doesn't currently call any log/format machinery, plus a switch
   to add a `log::info!()` to it. Measure the closure size delta.
   We expect the same cliff at miniature scale (dozens of sections
   → hundreds or thousands).

2. **Trace one cascade tendril** with `GRAFT_LOG`: pick a single
   surprise inclusion from fallback-string's closure (e.g. one of
   the `Layout::for_value_raw` instances), find why its
   trans_hash mismatched base's. Likely chain:
   `fallback → log::info! invocation → format args builder → ...
   → core::alloc::Layout::for_value_raw → reloc to anon string
   indirectly`.

3. **Build the anon-content-match fix** (M1.m.2 hybrid):
   - scan-time synthetic name per `.rodata..Lanon.*`
   - base post-link unique-byte-match + symhash entry
   - prune surrogate plumbing
   - measure fallback-string again

4. **Stretch goal**: for the `.rodata.str1.*` (merged-strings)
   section that participates in many of these chains, per-string
   sub-sectioning (split at NUL boundaries during scan, virtual
   sub-sections each with own trans_hash). Probably needed to
   really kill the cliff — anon-only may help but not eliminate it.

5. **If the cliff vanishes after (3+4)**: rerun this matrix on
   roborack3 and see whether fallback-string drops back into the
   <100-KB band where the other cells live.

## Runner

`/tmp/run_experiments.py` — Python runner that drives the matrix.
Mutators are deterministic source rewrites; runs revert before and
after each cell. Outputs `/tmp/graft-exp-runs/results.tsv`,
`results.json`, and per-cell `.graftlog` + `.cargo.log` artifacts.
Each cell is ~10–15 s of cargo time + ~4 s of graft; total wall
clock for 8 cells ≈ 2 minutes (post-warm sccache, esp-idf already
built).
