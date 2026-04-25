# Dev environment & hardware workflow

ESP32-S3 work runs inside a Docker container so the Xtensa toolchain
(rustc-esp fork, GCC, clang) stays out of the host. The container is
managed directly with three small scripts in `docker/` — no
devcontainer.json / VSCode dependency.

## First-time setup

```sh
docker/build.sh   # build the image (graft-esp32s3-dev:latest)
docker/up.sh      # start the long-lived container (named graft-esp32s3)
```

`up.sh` is idempotent — running it again removes the existing container
and starts a fresh one. The image takes ~5 min on first build (most of
it pulling the espressif base image and recompiling espflash); rebuilds
of the dev image after Dockerfile edits are seconds.

Cargo registry, git db, and the container-side `target/` dir live in
named volumes so they survive container recreate. The repo is
bind-mounted at `/workspace`, so edits round-trip live between host
and container. The host's `target/` is *also* bind-mounted at
`/host_target/` (read-only) so the host-built `graft` binary
(`x86_64-unknown-linux-musl/release/graft`) is reachable from inside
the container — that's how `linker = "/usr/local/bin/graft"` (a
symlink baked into the image) resolves.

## Running things

```sh
docker/exec.sh                          # interactive bash
docker/exec.sh cargo build              # one-shot inside container
docker/exec.sh espflash board-info \
    --port /dev/ttyACM0                 # talk to connected hardware
```

`exec.sh` uses plain `bash -c`, not `bash -lc` — the base image's
`.bashrc` early-returns for non-interactive shells, and `/etc/profile`
re-initializes `PATH` in a way that drops the Xtensa toolchain. The
Dockerfile bakes everything we need into `ENV`.

## Hardware

The ESP32-S3 dev kit shows up on the host at `/dev/ttyACM0` (native USB
JTAG/serial — no FTDI). Container sees it because:

- `--privileged` + bind-mount `/dev` and `/run/udev` (devices appear
  live without restarting the container).
- `esp` user is in `dialout` and `plugdev` so it can open the port
  without sudo.

If `espflash board-info` hangs or errors, double-check the cable is in
the **USB** (not UART) port on the dev kit, and that no other process
on the host has the port open (e.g. a leftover `picocom` / `screen`).

## Build / flash / monitor

There's a reference no_std fixture at `esp32s3-hello/`. Its
`.cargo/config.toml` wires `linker = "/usr/local/bin/graft"`, so
every `cargo build` goes through graft. With `GRAFT` unset, graft
runs in passthrough mode (forwards argv to `xtensa-esp32s3-elf-gcc`
unchanged), so a vanilla build "just works":

```sh
cd /workspace/esp32s3-hello
cargo build --release

espflash flash --port /dev/ttyACM0 \
    target/xtensa-esp32s3-none-elf/release/esp32s3-hello

espflash monitor --port /dev/ttyACM0 \
    --elf target/xtensa-esp32s3-none-elf/release/esp32s3-hello
```

`cargo run --release` also works (the runner is `espflash flash
--monitor`), but explicit `espflash monitor` is easier to capture in
non-interactive contexts — pass `--non-interactive` and a `timeout` if
you just want to grab a few seconds of output.

For the incremental loop, set `GRAFT` to switch modes:

```sh
# Clean build that captures base layout in .graft.* sidecar sections.
GRAFT=base cargo build --release

# Save the reference ELF for later overlay builds.
cp target/xtensa-esp32s3-none-elf/release/esp32s3-hello /tmp/base.elf

# Edit a source file, then build an overlay against the saved base.
GRAFT=overlay GRAFT_BASE_ELF=/tmp/base.elf cargo build --release
```

Each link emits a JSON line to `<output>.graft.log` recording mode,
input bytes, output bytes, and elapsed seconds. (rustc captures the
linker's stderr/stdout, so file-based telemetry is the only reliable
channel — see `graft/src/telemetry.rs`.) Running graft directly
without `cargo` still works for debugging; just give it the same
argv rustc would.

## Snapshots

`docker commit graft-esp32s3 graft-esp32s3-dev:<tag>` snapshots the
running container's filesystem (handy if you've installed extra
tooling and want to roll back). The named cargo / target volumes are
not part of the image — preserve those separately with `docker volume`
commands if you need to.

## Workspace layout note

`esp32s3-hello/` is excluded from the workspace (`Cargo.toml`
`workspace.exclude`) because it pins the `esp` rust-toolchain channel
and the `xtensa-esp32s3-none-elf` target via its own
`.cargo/config.toml`. Including it would force the host crates to also
go through the esp toolchain.
