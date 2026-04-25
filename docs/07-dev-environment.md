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

Cargo registry, git db, and the `target/` dir live in named volumes so
they survive container recreate. The repo is bind-mounted at
`/workspace`, so edits round-trip live between host and container.

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

There's a reference no_std fixture at `esp32s3-hello/`. From inside the
container:

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
