# 09 — Working with roborack3

Status: historical bring-up notes. Point-in-time operational record for
running graft on a large real ESP32-S3 firmware; kept for rationale.

Bringing graft up against the user's real project at `~/roborack3` — a
much larger ESP32-S3 firmware than the `esp32s3-hello` fixture used
through M1.a–M1.o. This doc captures the dev-loop pieces that differ
from the fixture, so the next person sitting down can re-run a
graft-base build without rediscovering the rough edges.

## Container

Don't reuse the user's `roborack` devcontainer — that one is mounted
on `/home/eric/roborack` (without the `3`) and shares a cargo cache
with their interactive workflow. We bring up a **separate** container
on the same image so an in-flight graft build doesn't stamp on what
the user has open.

```bash
docker run -d --name graft-roborack3 --privileged --network host \
  -v /home/eric/roborack3:/workspaces/roborack3 \
  -v /home/eric/projects/incremental_compilation:/workspaces/graft \
  -v graft-roborack3-cargo:/usr/local/cargo \
  -v graft-roborack3-sccache:/home/esp/.cache/sccache \
  -v /dev:/dev \
  -v /run/udev:/run/udev \
  -e CARGO_HOME=/usr/local/cargo \
  -w /workspaces/roborack3 \
  vsc-roborack-...:latest \
  sleep infinity
```

Replace the image tag with whichever `vsc-roborack-...` tag is
current on the host (`docker images | grep vsc-roborack`). Two
named volumes (`graft-roborack3-cargo`, `graft-roborack3-sccache`)
keep build caches isolated from the user's container.

The graft repo is bind-mounted at `/workspaces/graft` so the
container sees both projects without copying.

## Plain build (fallback-only)

`roborack3` defaults to all run modes; for graft bring-up we want
the smallest viable build.

### Pre-build: secrets.rs stub

`cfg/build.rs` panics if `cfg/src/secrets.rs` doesn't exist (Wi-Fi
credentials). The file is gitignored, so creating one from the
template is the standard workflow:
```bash
cp ~/roborack3/cfg/src/secrets.rs.example ~/roborack3/cfg/src/secrets.rs
```
The template's `"fillmeout"` placeholders are fine for graft
bring-up — we're not actually connecting to Wi-Fi.

```bash
docker exec graft-roborack3 bash -c \
  'cd /workspaces/roborack3 && cargo bflash --no-default-features --features run_mode_fallback'
```

`bflash` is an alias defined in `~/roborack3/.cargo/config.toml`:
```
bflash = "build --profile vehicle -Zbuild-std=std,panic_abort \
         --target xtensa-esp32s3-espidf --bin deploy"
```

First build is slow — `esp-idf-sys`'s `build.rs` clones a custom
ESP-IDF fork (`AutoPallet/esp-idf` at `v5.1.3-autopallet-9d54a97d`)
and bootstraps the IDF toolchain into `~/.embuild/`. Expect 30+
minutes the first time; incremental rebuilds after that go through
sccache.

Output ELF lands at:
```
target/xtensa-esp32s3-espidf/vehicle/deploy
```

## Swapping graft in as the linker

The project uses `ldproxy` (esp-idf-sys's wrapper) as its linker.
Graft can sit *in front* of ldproxy: graft inspects argv and either
runs base/overlay logic or forwards verbatim to `$GRAFT_REAL_LD`,
which we point at `ldproxy`.

Build the graft binary into a path the container can see:
```bash
cd /home/eric/projects/incremental_compilation
cargo build --release --target x86_64-unknown-linux-musl --manifest-path graft/Cargo.toml
```
The musl binary lands at `target/x86_64-unknown-linux-musl/release/graft`
on the host, visible inside the container at
`/workspaces/graft/target/x86_64-unknown-linux-musl/release/graft`.

Override the linker via env (no `.cargo/config.toml` edit needed):
```bash
GRAFT_BIN=/workspaces/graft/target/x86_64-unknown-linux-musl/release/graft

# Base link
docker exec graft-roborack3 bash -c "
  cd /workspaces/roborack3 && \
  rm -rf target/xtensa-esp32s3-espidf/vehicle/deps/deploy-* && \
  CARGO_TARGET_XTENSA_ESP32S3_ESPIDF_LINKER=$GRAFT_BIN \
  GRAFT_REAL_LD=ldproxy \
  GRAFT=base \
  GRAFT_ENTRY_SYMBOL=main \
  GRAFT_TEXT_SLACK_LEN=2000000 \
  GRAFT_RODATA_SLACK_LEN=400000 \
  GRAFT_DATA_SLACK_LEN=200000 \
  cargo bflash --no-default-features --features run_mode_fallback"

cp /workspaces/roborack3/target/xtensa-esp32s3-espidf/vehicle/deploy /tmp/base.elf

# Overlay link (after editing source)
docker exec graft-roborack3 bash -c "
  cd /workspaces/roborack3 && \
  rm -rf target/xtensa-esp32s3-espidf/vehicle/deps/deploy-* && \
  touch <edited-file> && \
  CARGO_TARGET_XTENSA_ESP32S3_ESPIDF_LINKER=$GRAFT_BIN \
  GRAFT_REAL_LD=ldproxy \
  GRAFT=overlay \
  GRAFT_BASE_ELF=/tmp/base.elf \
  GRAFT_ENTRY_SYMBOL=main \
  cargo bflash --no-default-features --features run_mode_fallback"
```

`GRAFT=base` runs base mode (scan inputs, compute trans_hashes,
exec real linker, attach `.graft.manifest` + `.graft.symhash` to
the output ELF, inject the synthetic slack `.o`).

`GRAFT=overlay` runs overlay mode (mutate `memory.ld` to retarget
overlay's regions at the slack vaddrs, mutate `sections.ld` to
strip `.flash_rodata_dummy` + INCLUDE the IRAM blocker, prune
inputs, link a tiny overlay ELF, splice + append into base.elf,
patch the trampoline at `main`).

## Status

| Step | State |
|---|---|
| Container up, host caches isolated | done |
| First fallback-only `cargo bflash` (no graft) | **done** (4m 20s incremental; cold first build with esp-idf clone is ~30 min) |
| Graft as base linker | **done** — `.graft.manifest`/`.graft.symhash` attached, slack symbols (`GRAFT_TEXT_SLACK`/`GRAFT_RODATA_SLACK`/`GRAFT_DATA_SLACK`) successfully placed by esp-idf's `*(.text.*)`/`*(.rodata.*)`/`*(.data.*)` wildcards |
| Graft as overlay linker | **done** — esp-idf layout port (memory.ld / sections.ld mutation, IRAM blocker via INCLUDE) lands |
| Hardware boot test | **done** — base flashes & boots; overlay edit (`v1` → `v2 EDITED`) flashes, boots, runs, serial shows `graft overlay test marker v2 EDITED` |

Picks up from M1.o (graft fixture pipeline working end-to-end on
ESP32-S3-DevKitC). M1.p milestone is "graft works as the base linker
for a real project on hardware."

### What actually worked first try

Base mode just worked — the only graft change needed was honoring
`--ldproxy-cwd <dir>` (the flag esp-idf-sys passes to ldproxy so the
real linker resolves relative archive paths like
`esp-idf/xtensa/libxtensa.a`). graft's base-mode + overlay-mode
entry points now `chdir` to that dir before scanning + linking.

Concrete results from `cargo bflash --no-default-features
--features run_mode_fallback` with graft as base linker:

```
[98] .graft.manifest   PROGBITS  ...   77 bytes
[99] .graft.symhash    PROGBITS  ...   1.3 MB
GRAFT_TEXT_SLACK   @ 0x4216ED84 (.flash.text region)
GRAFT_RODATA_SLACK @ 0x3C22C02C (.flash.rodata region)
GRAFT_DATA_SLACK   @ 0x3FC9A394 (DRAM)
```

ESP-IDF's `sections.ld.in` template uses `mapping[flash_text]` /
`mapping[flash_rodata]` / `mapping[dram0_data]` which after
preprocessing expand to wildcards including `*(.text.*)`,
`*(.rodata.*)`, `*(.data.*)`. The synthetic slack `.o`'s sections
(`.text.graft_slack`, `.rodata.graft_slack`, `.data.graft_slack`)
get scooped by those wildcards exactly the same way they do under
esp-hal. No esp-idf-specific code needed for base mode.

### Single graft for both layouts

A `Layout` enum dispatches between esp-hal and esp-idf at the start
of `setup_xtensa_layout`, picking based on which scripts appear in
the `-L` paths (esp-idf preferred when both exist). Each branch
reads, mutates, and writes its own flavor of the chain:

| Layer | esp-hal | esp-idf |
|---|---|---|
| memory regions | `memory.x` (`irom_seg`/`drom_seg`/`dram_seg`) | `memory.ld` (`iram0_2_seg`/`drom0_0_seg`/`dram0_0_seg`) |
| sections | `esp32s3.x` (with `.rotext_dummy`) | `sections.ld` (with `.flash_rodata_dummy`) |
| dummy clause | strip `.rotext_dummy` | replace `.flash_rodata_dummy` body with `_flash_rodata_dummy_start = ABSOLUTE(.)` stub |
| IRAM blocker | INCLUDE in mutated `esp32s3.x` before `INCLUDE "rwtext.x"` | INCLUDE near top of `SECTIONS{}` in `sections.ld`, before `.iram0.text` |
| blocker region | `> iram_seg` | `> iram0_0_seg` |

Both write `graft_blockers.ld` to `work_dir`; the INCLUDE inside
the mutated sections script picks it up. ld's section-ordering
puts the blocker first in the IRAM region, pushing overlay's
`.iram0.text` past base's used IRAM.

### Trampoline target on espidf: prefer `main` over `app_main`

The xtensa skip-then-load trampoline is **18 bytes**. esp-idf's
C-side `app_main` is exactly 16 bytes (4 instructions —
`link_patches();` then `rust_main();`), so trampolining at
`app_main` overflows by 2 bytes into the next function (`atexit`),
corrupting it. Use `GRAFT_ENTRY_SYMBOL=main` instead — Rust's
`fn main()` is 32 bytes, plenty of room. Base's `app_main` runs
unchanged and calls `main` as usual; the trampoline at `main`
redirects to overlay's `main`, which calls overlay's
`deploy::main` → `esp_main` → `fallback`.

Future work: graft could pick a longer base function automatically
(scan symhash for the entry's caller chain) or compress the
trampoline. Not urgent — `main` works.

### Slack sizes for roborack3

The fixture defaults (64 KB text / 64 KB rodata / 4 KB data) are
*much* too small for roborack3. The closure for any non-trivial
edit pulls in formatting machinery, `log::info!` plumbing, anyhow
glue, plus several support nodes' constructors:

```bash
GRAFT_TEXT_SLACK_LEN=2000000      # 2 MB
GRAFT_RODATA_SLACK_LEN=400000     # 400 KB
GRAFT_DATA_SLACK_LEN=200000       # 200 KB
```

Used during base-link via env. Tune down once an actual fixture
edit pattern is settled. (Without LTO — `--profile vehicle`
inherits `dev` — cross-TU inlining is reduced compared to the
M1.n fixture's `--release` build, but every constructor in
`fallback()` is a separate fn and they all land in the closure.)

## Open questions / known gotchas

- **Slack symbols** — verified working. Esp-idf's `sections.ld`
  wildcards (`*(.text.*)`, `*(.rodata.*)`, `*(.data.*)`) scoop the
  synthetic `.o`'s sections into the right output regions.

- **Entry symbol on espidf** — verified `app_main` exists at
  `0x42094300` in the built ELF. C-side `app_main` (from esp-idf-sys)
  jumps to Rust's `main` (at `0x4200474c`). Used `app_main` as the
  graft trampoline target.

- **Build cache invalidation.** Cargo doesn't always re-link when
  only env vars change (e.g. swapping `CARGO_TARGET_*_LINKER`).
  Workaround: `rm -f target/xtensa-esp32s3-espidf/vehicle/deps/deploy-*`
  before each graft invocation. Cleaner long-term: bake the linker
  choice into `.cargo/config.toml` (with graft conditional on
  whether `GRAFT` env is set).

- **`--ldproxy-cwd` honoring.** esp-idf-sys passes
  `--ldproxy-cwd <build-dir>` so the real linker resolves relative
  archive paths (e.g. `esp-idf/xtensa/libxtensa.a`). Graft now
  `chdir`s to that dir at the start of base + overlay modes so the
  pre-scan resolves the same paths. Idempotent — ldproxy still sees
  the flag in its argv during passthrough.

- **Base build size.** Plain build is 67 MB (vs 2.4 MB for the
  M1.n hello-world fixture). The .graft.symhash section alone is
  1.3 MB — larger because the project has thousands of symbols
  vs. dozens in the fixture. Encoding throughput matters more
  here than it did in the fixture; revisit if symhash attach
  time becomes the bottleneck.

- **Build profile.** `--profile vehicle` is the project's release
  profile. Verify graft's metadata-attach path works on the
  resulting ELF (fixture used `--release`; espidf builds may have
  different section layout).

- **First-build cost.** esp-idf clone + toolchain bootstrap takes
  tens of minutes. Subsequent builds reuse `.embuild/`. Avoid
  `cargo clean` unless necessary.
