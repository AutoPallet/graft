# Debugging identity and fold issues

How to dissect a wrong closure decision, an ICF fold refusal, or a
suspected `trans_hash` collision. Method distilled from the #42 and #46
investigations.

## Tools

- `GRAFT_DEBUG` flags (comma-separated; unknown flag is a hard error):
  - `dump-graph=<path>` — one line per scan node with stable cross-scan
    keys, from base and overlay links. The primary lockstep input.
  - `preserve-icf-inputs` — keep the `<output>.graft-icf/` rewritten
    objects after a base link instead of deleting them.
  - `icf-limit=<N>` — fold only the first N sorted ICF groups. Bisect
    knob: binary-search N to isolate the group that flips behavior.
  - `mismatch=<path>` — log every closure node that missed a
    base-section match (the "why did this re-emit" question).
  - `scan-timings` — per-phase scan wall times to stderr.
- `graft cache-info <base.elf>` — dump the manifest + section table;
  `--grep <hex>` filters by `trans_hash` substring, `--addr <addr>` by
  placed address. First stop for "what does base think this hash is".
- `graft dup-stats` / `graft scan-dump` — the scan's section/hash view
  of a link line, including content-identical groups.
- Output capture: rustc swallows linker stderr on success. Read
  `<output>.graft.log` (or set `GRAFT_LOG=<path>` — reset per run, all
  writers append), or run graft directly on a saved argv.

## Dissecting a fold pair / suspected collision

The ICF verifier names the pair on refusal: both symbols, their rcgu
objects, and the first differing offset (`target classes differ at
+0xNNN`). From there:

1. Reproduce with the pair isolated: `icf-limit` bisect until only the
   offending group folds, `preserve-icf-inputs` to keep the objects.
2. Byte-level look: `objdump -dr` / `readelf -r` both sections. Find
   the reloc covering the named offset; the two targets are the
   interesting divergence.
3. Walk down: for each of the two targets, compare *their* trans_hashes
   (`cache-info --grep`). Recurse until you find the first pair that is
   physically different but hashes equal — that pair names the
   canonicalization step that equated them (same-named locals across
   TUs, `.llvm.<id>` stripping, weak fallback, ...).
4. Lockstep dump: `dump-graph` from two independent scans of the same
   inputs, join rows on the stable keys, and diff the hash columns.
   This catches order-dependence (same content, different hashes) —
   the opposite failure from a collision.

House rules that keep the dissection honest: section identity within an
object is the physical index, never the name (same-named sections are
legal); "tests pass" can mean "tests didn't run" — force relinks
(`touch` a source; cargo does not fingerprint env vars) and verify a
link happened via the log before trusting a measurement.
