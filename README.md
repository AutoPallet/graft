# graft

Incremental **linking** for embedded and native Rust: relink only what an
edit changed, splice it into the previous binary, and flash only the
sectors that differ. No hot-patching, no runtime — the output is an
ordinary ELF that boots the normal way.

How it actually works: [`docs/how-it-works.md`](docs/how-it-works.md).

A full build links a **base** image once, recording where every input
section landed. After an edit, graft links only the transitive closure of
sections whose content changed — everything else resolves positionally
against the base — and writes the result into slack — empty space the
base link reserves up front — so the base image's layout never shifts. A
sector-diff flasher (`docker/flash-diff.py`) then writes
only the changed 4KB sectors, identified through per-sector hash
manifests keyed by the image's appended SHA-256.

```
BASE IMAGE (linked once; slack balloons reserved up front)

  +----------+----------------+------------+-------------+-----------+------------+
  |  .text   | GRAFT_TEXT     |  .rodata   | GRAFT_RO... |  .data    | GRAFT_DATA |
  |  code    |  _SLACK        |  consts    |  _SLACK     |  statics  |  _SLACK    |
  |          | (0xFF balloon) |            | (balloon)   |           | (balloon)  |
  +----------+----------------+------------+-------------+-----------+------------+
     foo()          ^                                        ^
                    |                                        |
   edit foo() -> overlay link emits only the changed closure |
                    |                                        |
                    v  splice new foo' into .text balloon    v  new/changed statics
  +----------+----------------+------------+-------------+-----------+------------+
  |  .text   | foo'  (spliced |  .rodata   | (unchanged) |  .data    | (spliced)  |
  |  code    |  into slack)   |  consts    |             |  statics  |            |
  +----+-----+----------------+------------+-------------+-----------+------------+
       |          ^                             ^
       | trampoline (long jump)                 | unchanged refs in foo' resolve
       +--> foo'                                 | POSITIONALLY into base via
   old foo() entry redirected to new copy        anchors (base addr as constant)
```

Unchanged references never move: an anchor pins them to base's address
as a constant. Only foo's entry is trampolined; the rest of base is
byte-for-byte untouched, which is what makes the sector-diff flash cheap.

**Status:** research prototype. Validated on ESP32-S3 hardware (xtensa,
bare metal and esp-idf/std) and on x86_64-musl (rust-analyzer). Not
published as a crate; no stability guarantees.

## Measured results

Large ESP32-S3 project (esp-idf + Rust std, ~2,900 input objects /
~173,000 input sections, 6.4MB app image), one-line edit loop on real
hardware:

|                    | full build            | graft edit loop  | win  |
|--------------------|-----------------------|------------------|------|
| link               | 135.9s                | 4.5–4.8s         | ~29× |
| flash              | 91.2s (1,564 sectors) | 2.7–3.2s (5–12 sectors) | ~30× |
| edit → running     | ~3m 45s               | 13–20s           | ~13× |

Typical overlay payload: 0.8–22KB spliced into a 6.4MB image. Of the
overlay link time, ~4.0s is input scanning/hashing — a persistent scan
cache is the next lever.

Native x86-64 (rust-analyzer, ~470k input sections): overlay relink
4.5s vs 138.5s full link, patched binary verified by execution.

Correctness is validated on-device by an abuse matrix over edit classes
that historically produce *silent* incremental-link bugs:

- changed static initializers with unchanged users,
- single-user edits against base-resident statics,
- zero-init `.bss` twins (aliasing canaries),
- string/rodata edits,
- function bodies reached only through static function pointers,
- cross-crate edits,

each checked against computed expected values at boot.

## Using it

graft is a linker shim: rustc invokes it in the linker seat, and it
either does the graft work or forwards argv to the real linker
(`$GRAFT_REAL_LD`, default `cc`). Wire it in `.cargo/config.toml`:

```toml
[target.xtensa-esp32s3-none-elf]
linker = "/path/to/graft"

[env]
GRAFT = "auto"                            # engage graft (see modes below)
GRAFT_REAL_LD = "xtensa-esp32s3-elf-gcc"  # real linker graft forwards to
```

Bare-metal xtensa also needs `GRAFT_TLS_SLACK_LEN = "0"` (no TLS runtime;
see env table) — full working config in
`esp32s3-hello/.cargo/config.toml`.

The target's linker script must "scoop" graft's slack input sections
(`*.graft_slack`) into base's normal output sections via wildcard rules
(`*(.text.*)`, `*(.rodata.*)`, etc.). Without a matching rule ld
orphan-places the slack — it lands wherever ld guesses and can silently
change segment layout. graft's base link self-checks this and fails
loudly (`check_slack_scooped`) on any orphaned `*.graft_slack` output
section, so the failure is at link time, not on-device.

The `GRAFT` variable picks the mode:

- **unset** — passthrough; graft forwards to the real linker unchanged.
  This is the path IDEs, `cargo check`, and `build.rs` probes take.
- `auto` — self-managing. First link for a given output is a full base
  link (a snapshot is kept next to the output); later links overlay
  against it. Any overlay failure falls back to a full base relink, so
  the build always succeeds — just slower on the fallback. `cargo build`
  "just works" incrementally.
- `base` / `overlay` — the two phases run explicitly (overlay needs
  `GRAFT_BASE_ELF`). Used by the test harnesses.
- `passthrough` — explicit opt-out, same as unset.

A set-but-unrecognized `GRAFT` value is a hard error, never a silent
passthrough (a typo would otherwise ship an un-instrumented "base").

Subcommands: `graft combine` (splice a base + overlay pair),
`graft scan-dump` / `graft dup-stats` (inspect the section/hash table),
`graft cache-info <base.elf>` (dump the manifest + section table;
`--grep <substr>` filters entries by `trans_hash` hex substring,
`--addr <addr>` by placed address).

## Environment variables

| Variable | Effect |
|---|---|
| `GRAFT` | Mode: unset/`passthrough`, `auto`, `base`, `overlay`. Unrecognized value is a hard error. |
| `GRAFT_REAL_LD` | Real linker graft execs (default `cc`; bare-metal sets e.g. `xtensa-esp32s3-elf-gcc`). |
| `GRAFT_BASE_ELF` | `overlay` mode: base ELF to prune against. `auto` uses its own snapshot instead. |
| `GRAFT_REBASE` | `auto` mode: `1` forces a fresh base link, discarding the snapshot. |
| `GRAFT_ENTRY_SYMBOL` | Move the single overlay trampoline off `main` (debugging; default `main`). |
| `GRAFT_TEXT_SLACK_LEN` | Bytes of `.text` slack the base link reserves for future overlays. |
| `GRAFT_RODATA_SLACK_LEN` | Bytes of `.rodata` slack reserved at base link. |
| `GRAFT_DATA_SLACK_LEN` | Bytes of `.data` slack reserved at base link. |
| `GRAFT_TLS_SLACK_LEN` | Bytes of TLS slack reserved; `0` opts out (bare-metal xtensa has no TLS runtime). |
| `GRAFT_ICF` | `1` to enable identical-code folding (ICF): fold identical Rust code sections at base link (default off). |
| `GRAFT_ICF_VERIFY` | Byte-level fold verifier (default on); `0` disables. |
| `GRAFT_LOG` | Path for the per-link decision/telemetry log. |
| `GRAFT_DEBUG` | Comma-separated debug flags; unknown flag is a hard error. Flags: `preserve-icf-inputs`, `dump-graph=<path>` (dump the closure graph), `scan-timings` (per-phase scan timings to stderr), `icf-limit=<N>` (fold only the first N sorted ICF groups — bisect knob), `mismatch=<path>` (log nodes that missed a base-section match). |

Slack is reserved once at base-link time and can never grow at combine
time; the overlay link asserts its payload fits and bails (to a full
relink under `auto`) if not.

## Why xtensa is hard

GNU ld rewrites xtensa code as it links (deleting, narrowing, and
widening instructions), so an input byte's address in the base image
can't be computed by offset. graft replays ld's exact set of edits —
transcribed from binutils source — to locate each byte
(`docs/16-relaxation-walk.md`). When it can't account for a byte, a
read-only or executable target is re-emitted into the overlay (base's
code keeps calling its own copy), while a refusal on mutable data is a
hard error, since re-emitting would fork the variable into two live
copies. Under `GRAFT=auto` any such error falls back to a full relink.
It accounts for all 10,000 relaxed
sections in the reference corpus, and the same engine verifies
470,558/470,558 sections on x86-64 (where no relaxation occurs) as a
self-check.

## Layout

- `graft/` — the linker shim (scan, closure, prune, relax walk, splice)
- `esp32s3-hello/` — bare-metal fixture
- `docker/` (repo root) — `hw-test.sh` hardware loop, `flash-diff.py`
  manifest-based sector-diff flasher
- `docs/` — maintained design docs (`how-it-works.md`, 14, 16, 07) plus
  `docs/worklogs/` write-once records (start at `docs/README.md`)

## License

Licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
