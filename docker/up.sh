#!/usr/bin/env bash
# Start (or restart) the long-running dev container. Idempotent: if a
# container with the same name already exists it's removed first so a
# fresh image takes effect.
#
# The container sleeps forever; use `docker/exec.sh ...` to run commands
# inside it. Caches live in named volumes so they survive container
# recreate; the workspace is bind-mounted so edits round-trip live.
set -euo pipefail

NAME="graft-esp32s3"
IMAGE="graft-esp32s3-dev:latest"
ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"

if docker container inspect "$NAME" >/dev/null 2>&1; then
    echo "removing existing $NAME"
    docker rm -f "$NAME" >/dev/null
fi

docker run -d \
    --name "$NAME" \
    --privileged \
    --network host \
    -v /dev:/dev \
    -v /run/udev:/run/udev \
    -v "$ROOT":/workspace \
    -v graft-esp32s3-cargo-registry:/home/esp/.cargo/registry \
    -v graft-esp32s3-cargo-git:/home/esp/.cargo/git \
    -v graft-esp32s3-target:/workspace/target \
    -w /workspace \
    "$IMAGE" \
    sleep infinity >/dev/null

echo "started $NAME"
