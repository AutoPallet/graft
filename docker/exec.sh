#!/usr/bin/env bash
# Run a command inside the dev container. With no args, opens a bash shell.
# Examples:
#   docker/exec.sh                       # interactive bash
#   docker/exec.sh cargo build           # one-shot
#   docker/exec.sh espflash board-info   # use connected hardware
set -euo pipefail
NAME="graft-esp32s3"
if [ $# -eq 0 ]; then
    exec docker exec -it "$NAME" bash
else
    exec docker exec -it "$NAME" bash -c "$*"
fi
