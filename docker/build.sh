#!/usr/bin/env bash
# Build the dev image. Run from anywhere; resolves repo root via git.
set -euo pipefail
ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
docker build -t graft-esp32s3-dev:latest -f "$ROOT/docker/Dockerfile" "$ROOT/docker/"
