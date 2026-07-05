# 10 — Mutation experiments on roborack3

Status: historical measurement (M1.r era). Closure-cost numbers below
predate later resolver/ICF changes; kept for the qualitative finding
(closure cost is site-determined, log-machinery edits cascade).

A 4×2 matrix of overlay rebuilds against the user's real ESP32-S3
firmware (`~/roborack3`, fallback-only build), measuring how the
graft closure cost (and the wall-clock breakdown) responds to
small source mutations at different sites.

This doc has been refreshed after the M1.r series (SHN_ABS reloc
rewriting, archive walking, lazy member discovery, `-nostartfiles`).
The original numbers from M1.q.1 are preserved at the bottom for
historical reference. Hardware-validated: `cli-numeric` boots cleanly
through wifi connect + HTTP server on hardware.

## Method

For each cell:

1. `git checkout` the target file (clean state).
2. Apply a single deterministic source mutation.
3. Force a re-link by removing the deploy artifact + `touch`-ing
   the source.
4. Run `cargo bflash --no-default-features --features
   run_mode_fallback` with `GRAFT=overlay`,
   `GRAFT_BASE_ELF=/tmp/base.elf`, and
   `GRAFT_ENTRY_SYMBOL=_ZN6deploy9run_modes8fallback8fallback17h…E`
   (mangled `fallback`). Using a deeper-than-`main` entry avoids the
   re-emitted-stdio-mutex hang we hit with the trivial choice.
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

## Results (post-M1.w)

All eight cells link cleanly and produce overlays whose combined
size equals base.elf — fully spliced into base's reserved slack
regions, no extra LOAD segments. Hardware-validated end-to-end on
two cells (`wifi-string` and `fallback-string`); both reach serial
output at the mutated code path.

| Cell | Closure (sections) | Overlay payload | Pruned objs | Trampolines | Total |
|---|---:|---:|---:|---:|---:|
| fallback-string | 15,517 | 1,186,103 B | 51 | 1 | 7.4s |
| fallback-numeric | 24 | 1,496 B | 3 | 1 | 5.4s |
| wifi-string | 88 | 7,120 B | 3 | 1 | 5.4s |
| wifi-numeric | 97 | 7,932 B | 3 | 1 | 5.4s |
| cli-string | 184 | 14,876 B | 4 | 1 | 5.4s |
| cli-numeric | 26 | 1,532 B | 4 | 1 | 5.4s |
| cfg-string | 38 | 12,968 B | 4 | 0 | 5.4s |
| cfg-numeric | 38 | 12,964 B | 4 | 0 | 5.4s |

Notes:

- `fallback-string` is the heaviest cell because adding `log::info!`
  to a function that previously logged nothing pulls in the entire
  log + format + panic-infrastructure cascade. The 1.16 MB payload
  fits in the slack reservations; combined size still equals base.
- `cfg-*` have 0 trampolines because the change is in `cfg`'s HTTP
  surface — touched only when the dev HTTP server runs, which the
  fallback profile doesn't. The closure stops above the entry
  symbol's reachability.
- `t_total` is dominated by `t_scan` (~3.8s) for small cells.
  fallback-string's 7.4s is mostly graft's real-link step (1.8s)
  plus prune (233ms) — both proportional to the much larger
  closure / pruned-input volume.

The `fallback-string` regression in earlier writeups (anon-name
drift, then mutex-init panic at boot) is now resolved by the
M1.s through M1.w changes:

- M1.s: content-keyed symhash table, names folded into identity.
- M1.t: per-target SHN_ABS anchors (`__graft_sym_<symhash>`) instead
  of single `__graft_const + addend`, fixing GOTPCREL through prune.
- M1.u: classify_bind treats UND as Global so demand-load actually
  pulls archive members satisfying UND refs.
- M1.v: synthetic phantom nodes for `.init_array`-class outputs;
  drops `.note.*` / `.eh_frame*` / `.ctors`-class roots that the
  runtime consumes via segment header.
- M1.w: pass-1 prefers Global > Weak (matches ld); scan respects
  already-defined names + applies `--wrap=` rename to demand-load
  lookups so wrap functions get pulled.

Phase timings (graft-internal — these exclude rustc compile time):

| Cell | scan | prune | link | combine |
|---|---:|---:|---:|---:|
| fallback-string | 3.8s | 233.2ms | 1.8s | 75.2ms |
| fallback-numeric | 3.9s | 1.6ms | 17.3ms | 80.3ms |
| wifi-string | 3.8s | 4.5ms | 18.9ms | 76.2ms |
| wifi-numeric | 3.8s | 4.2ms | 19.2ms | 92.2ms |
| cli-string | 3.8s | 4.5ms | 20.7ms | 83.7ms |
| cli-numeric | 3.8s | 2.1ms | 18.7ms | 73.8ms |
| cfg-string | 3.9s | 2.3ms | 17.6ms | 76.1ms |
| cfg-numeric | 3.9s | 2.2ms | 17.1ms | 79.9ms |

(`closure` walk is microseconds across all cells — below printf precision.)

(`closure` column is microseconds — counts of section walks the
trans_hash classification touches; the timing field is below the
graftlog's printf precision for these closures. `total` is dominated
by `scan`.)

Compile time (rustc, before graft sees anything; mostly cached
incremental — full clean build of base was 4m20s):

| Cell | rustc | graft total | sum |
|---|---:|---:|---:|
| fallback-numeric | 11.3s | 4.5s | 15.8s |
| wifi-string | 11.7s | 4.9s | 16.6s |
| wifi-numeric | 8.4s | 3.5s | 11.9s |
| cli-string | 14.0s | 3.5s | 17.5s |
| cli-numeric | 13.9s | 3.5s | 17.4s |
| cfg-string | 14.6s | 3.5s | 18.1s |
| cfg-numeric | 8.8s | 3.5s | 12.3s |

## Comparison vs M1.q.1 baseline

| Cell | M1.q.1 closure / payload | Current closure / payload | Δ payload |
|---|---|---|---:|
| fallback-string | 15,604 / 1,195,810 B | (fails) | — |
| fallback-numeric | 41 / 28,002 B | 25 / 1,500 B | **−94.6%** |
| wifi-string | 101 / 34,450 B | 92 / 7,616 B | **−77.9%** |
| wifi-numeric | 100 / 34,450 B | 101 / 8,412 B | **−75.6%** |
| cli-string | 735 / 91,378 B | 186 / 15,136 B | **−83.4%** |
| cli-numeric | 706 / 89,518 B | 27 / 1,536 B | **−98.3%** |
| cfg-string | 38 / 39,166 B | 39 / 12,972 B | **−66.9%** |
| cfg-numeric | 38 / 39,162 B | 39 / 12,968 B | **−66.9%** |

Closures shrink 4–25× for the sites that previously cascaded through
monomorphic infrastructure (`cli-string` 735→186, `cli-numeric`
706→27). Payloads shrink 67–98% — the M1.q.1 numbers carried a
~27 KB PROVIDE-backstop floor (every overlay shipped a copy of the
linker-script-wrap'd unwind/runtime helpers regardless of the actual
edit) plus extensive ride-along from libstdc++ statics that lazy
archive discovery now skips.

(An *earlier* version of this doc reported sub-500-byte payloads for
several cells. That was a graft correctness bug: cross-CGU references
within the closure were being SHN_ABS-rewritten to base's stale
addresses, ld's --gc-sections then dropped the closure-included
sections from overlay because they appeared unreachable, and the
mutation silently ran base's old code at runtime. Fixed in M1.r.3 —
see commit log. Hardware verification with the wifi-string mutation
now produces the expected new log line at runtime.)

Total link wall time dropped from ~4.7s → ~3.5s (−25%) across the
matrix; scan went from 4.4s → 3.2s after lazy archive member
discovery.

## Combined-ELF size

Every cell that succeeds produces a combined ELF of exactly
**70,655,288 bytes** = base.elf's size. **No PT_LOAD gets appended
to base anymore** — every overlay byte fits in graft's reserved
slack regions and is spliced in. (Pre-M1.r runs would append a stray
`.iram0.vectors` carrying gcc-injected `_init` past base's IRAM, the
silent root cause of the "boot hangs at app_main" regression that
was finally untangled.)

## Observation 1: the fallback-string cliff (revised)

In M1.q.1, `fallback-string` produced 15,604 closure sections /
1.2 MB payload. The hypothesis at the time pinned it on
unstable-name relocs into `.rodata..Lanon.*` from new format-machinery
chains.

After M1.q.2's content-stable reloc encoding + M1.r's SHN_ABS path,
the cliff disappears for *most* mutations — the fallback-numeric cell
now matches the other "depth-1 numeric" cells at hundreds of bytes.

`fallback-string` still fails, but for a different reason: the new
chain pulls in serde_urlencoded code that references rustc-emitted
*anonymous sections* by name. Anon names embed a CGU fingerprint
that's not stable across base/overlay builds, so prune can't resolve
them through base. The deferred M1.m.2 anon-content-match plan
addresses this by hashing anon contents and PROVIDE'ing them via a
synthetic name.

Until M1.m.2 lands, `fallback-string` is the canary case for that
class of failure.

## Observation 2: cfg cells produce zero trampolines

cfg-string and cfg-numeric land at 100 B payload with **0**
trampolines. That's because their mutations live in a config crate
whose only effect is changing `Config::compute`'s embedded constants
— not redirecting any function entry. Overlay just splices the
changed constant tables into base's rodata slack; nothing in base's
text path needs to be redirected. Total link is identical (3.5s).

## Observation 3: phase timings are dominated by scan

`scan` is **3.2–4.6 s** per cell. The variability is run-to-run
filesystem cache; cold runs are ~4.3s, warm runs ~3.3s. That's the
floor cost: parsing every reachable input object across rust crates
+ libgcc/libc/libstdc++/IDF components, building the graph, running
Tarjan, computing trans_hashes.

`link` (real linker, ld through ldproxy) is **16–26 ms** in every
cell — tiny, because graft's pruned input is small and SHN_ABS-
encoded so ld has almost nothing to do.

`closure` (the trans_hash-driven walk) is **microseconds** — not
visible in the wall-clock budget.

`prune` is **2–5 ms** — proportional to closure size, also negligible.

`combine` is **75–110 ms** — section splicing + ELF rewrite.

The next-tier optimization would be **parallelism in scan**: blake3
+ ELF parsing across the ~1,400 reachable objects on multiple cores.
That's the leftover speedup; everything else is post-scan in the
millisecond range.

## Runner

`/tmp/run_experiments.py` — Python runner that drives the matrix.
Mutators are deterministic source rewrites; runs revert before and
after each cell. Outputs `/tmp/graft-exp-runs/results.tsv`,
`results.json`, and per-cell `.graftlog` + `.cargo.log` artifacts.
Each cell is ~10–15 s of cargo time + ~3.5 s of graft; total wall
clock for 8 cells ≈ 2 minutes (post-warm sccache, esp-idf already
built).

---

## Historical: M1.q.1 baseline (pre-SHN_ABS, pre-lazy-archive)

Preserved for reference. PROVIDE-backstop link, eager archive walking,
no `-nostartfiles`. Hardware boot was never validated for these
configs — the link succeeded but every overlay binary hung at
`Calling app_main()` due to gcc auto-injected `_init` ending up in a
new PT_LOAD past base's IRAM (resolved by M1.r's `-nostartfiles`).

| Cell | Closure | Overlay payload | Pruned objs | Total |
|---|---:|---:|---:|---:|
| fallback-string | 15,604 | 1,195,810 (1.2 MB) | 405 | 6.1s |
| fallback-numeric | 41 | 28,002 (27 KB) | 4 | 3.9s |
| wifi-string | 101 | 34,450 (34 KB) | 8 | 4.0s |
| wifi-numeric | 100 | 34,450 (34 KB) | 8 | 4.0s |
| cli-string | 735 | 91,378 (89 KB) | 35 | 4.0s |
| cli-numeric | 706 | 89,518 (87 KB) | 35 | 4.1s |
| cfg-string | 38 | 39,166 (38 KB) | 4 | 4.0s |
| cfg-numeric | 38 | 39,162 (38 KB) | 4 | 4.0s |
