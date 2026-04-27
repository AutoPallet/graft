# 09 — Working with roborack3

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
docker exec graft-roborack3 bash -c '
  cd /workspaces/roborack3 && \
  CARGO_TARGET_XTENSA_ESP32S3_ESPIDF_LINKER=/workspaces/graft/target/x86_64-unknown-linux-musl/release/graft \
  GRAFT_REAL_LD=ldproxy \
  GRAFT=base \
  GRAFT_ENTRY_SYMBOL=app_main \
  cargo bflash --no-default-features --features run_mode_fallback'
```

`GRAFT=base` makes graft run base mode (scan inputs, compute
trans_hashes, exec real linker, attach `.graft.manifest` +
`.graft.symhash` to the output ELF). `GRAFT_ENTRY_SYMBOL=app_main`
points at the ESP-IDF entry — espidf-sys's `app_main` is what the
runtime calls into; it's what overlay's trampoline will redirect.

For overlay rebuilds:
```bash
GRAFT=overlay \
GRAFT_BASE_ELF=/path/to/saved/base.elf \
GRAFT_ENTRY_SYMBOL=app_main \
cargo bflash --no-default-features --features run_mode_fallback
```

## Status

| Step | State |
|---|---|
| Container up, host caches isolated | done |
| First fallback-only `cargo bflash` (no graft) | **done** (4m 20s incremental; cold first build with esp-idf clone is ~30 min) |
| Graft as base linker | **done** — `.graft.manifest`/`.graft.symhash` attached, slack symbols (`GRAFT_TEXT_SLACK`/`GRAFT_RODATA_SLACK`/`GRAFT_DATA_SLACK`) successfully placed by esp-idf's `*(.text.*)`/`*(.rodata.*)`/`*(.data.*)` wildcards |
| Graft as overlay linker | **blocked on esp-idf linker-script port** — see "esp-idf vs esp-hal layout" below |
| Hardware boot test | not started |

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

### Blocker for overlay mode: esp-idf's linker-script chain

`overlay.rs::setup_xtensa_layout` was written for esp-hal's layout
and looks for files that don't exist under esp-idf:

| esp-hal expects | esp-idf has |
|---|---|
| `memory.x` (with `irom_seg`/`drom_seg`/`dram_seg` named regions) | `memory.ld` with `iram_seg`/`drom_seg`/`dram_seg`/`extern_ram_seg`/etc. |
| `esp32s3.x` (containing `.rotext_dummy`) | `sections.ld.in` template, processed into `sections.ld` at cmake build time |
| esp-hal's `*.x` files via `-L <esp-hal-out-dir>` | `-L <esp-idf-out>/build/esp-idf/esp_system/ld` etc. |

Overlay mode hits this immediately:
```
graft overlay: memory.x not found in any -L path (6 searched)
```

The work needed for overlay support:
1. Detect esp-idf vs esp-hal at runtime (look for `memory.ld` first;
   fall back to `memory.x`).
2. Write an esp-idf-flavored `mutate_memory_ld` that bumps the
   relevant region ORIGINs to the slack vaddrs (region names
   differ — `iram_seg`, `dram_seg` are shared, but the IROM/DROM
   regions are merged into one external-flash region and the
   address arithmetic is different).
3. Find the equivalent of esp-hal's `.rotext_dummy` strip — esp-idf
   has `.flash_rodata_dummy` which serves the same DROM/IROM
   alignment role; need to either remove it or work with it.
4. Update the IRAM blocker (`graft_blockers.ld`) for esp-idf's
   `iram_seg` (which has different ORIGIN/LENGTH than esp-hal's).

Estimate: ~300-500 LOC of plumbing, mostly in `overlay.rs`.
Behavior should be identical conceptually; the linker-script
mutation just runs against a different starting layout.

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
