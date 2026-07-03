#!/usr/bin/env bash
# Hardware validation loop for the esp32s3-hello fixture (dev
# convenience — the primary correctness gate is the x86 e2e suite,
# which runs without hardware; this script checks the same invariants
# end-to-end on the real chip).
#
# Sequence:
#   1. rebuild host musl graft (the container's linker)
#   2. base build (Hello, GREETING_IDX unset) with the -Map oracle on
#   3. flash base, assert probe + counter output
#   4. overlay build (Howdy via GREETING_IDX=1) against the base
#   5. assert the closure re-emits neither `main` (trampoline cut)
#      nor `.rwtext` (unchanged IRAM resolves positionally)
#   6. flash combined, assert probes + Howdy + counters
#   7. restore: rebuild + flash the Hello base
#
# Requirements: graft-esp32s3 container running (docker/up.sh), device
# on /dev/ttyACM0. NEVER add git commands here — /workspace in the
# container is the bind-mounted host checkout.
set -euo pipefail

ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
PORT="${GRAFT_HW_PORT:-/dev/ttyACM0}"

run() { docker exec graft-esp32s3 bash -c "$1"; }

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

monitor() {
    # Attaching resets the device, so the capture starts at boot.
    run "timeout 12 espflash monitor --port $PORT --non-interactive 2>/dev/null" || true
}

build() {
    # $1 = extra env. Force a relink (cargo doesn't track GRAFT) by
    # removing prior outputs; GREETING_IDX changes recompile on their
    # own via rustc's dep-info env tracking.
    run "cd /workspace/esp32s3-hello &&
         rm -f target/xtensa-esp32s3-none-elf/release/esp32s3-hello \
               target/xtensa-esp32s3-none-elf/release/deps/esp32s3_hello-* 2>/dev/null;
         $1 cargo build --release 2>&1 | tail -2"
}

echo "== 1/7 host musl graft"
(cd "$ROOT" && cargo build --release --target x86_64-unknown-linux-musl -p graft)

echo "== 2/7 base build (Hello)"
build "GRAFT=base GRAFT_ENTRY_SYMBOL=graft_entry"
run "cp /workspace/esp32s3-hello/target/xtensa-esp32s3-none-elf/release/esp32s3-hello /tmp/base.elf"

echo "== 3/7 flash base + verify"
run "espflash flash --port $PORT /tmp/base.elf >/dev/null 2>&1"
out=$(monitor)
grep -q "GE4: greeting load ok = Hello" <<<"$out" || fail "base GE probes (got: $(tail -c 400 <<<"$out"))"
grep -q "Hello from ESP32-S3! mut=2 atomic=2 ram=3" <<<"$out" || fail "base counters"

echo "== 4/7 overlay build (Howdy)"
build "GREETING_IDX=1 GRAFT=overlay GRAFT_BASE_ELF=/tmp/base.elf GRAFT_LOG=/tmp/overlay.log"
run "head -1 /tmp/overlay.log"

echo "== 5/7 closure invariants"
run 'grep -qE "text\.main|:: \.rwtext " /tmp/overlay.log' \
    && fail "closure re-emits main or .rwtext (trampoline cut / IRAM identity broken)"
run 'grep -q "text.graft_entry" /tmp/overlay.log' || fail "closure missing graft_entry"

echo "== 6/7 flash combined + verify"
run "espflash flash --port $PORT /workspace/esp32s3-hello/target/xtensa-esp32s3-none-elf/release/esp32s3-hello >/dev/null 2>&1"
out=$(monitor)
grep -q "GE1: entered overlay graft_entry" <<<"$out" || fail "overlay GE1 (trampoline / printer)"
grep -q "GE3: ram_resident_step ok = 42" <<<"$out" || fail "overlay GE3 (IRAM positional resolution)"
grep -q "GE4: greeting load ok = Howdy" <<<"$out" || fail "overlay GE4 (edit not applied?)"
grep -q "Howdy from ESP32-S3! mut=2 atomic=2 ram=3" <<<"$out" || fail "overlay counters (mutable-static aliasing?)"

echo "== 7/7 restore Hello base"
build "GRAFT=base GRAFT_ENTRY_SYMBOL=graft_entry"
run "cp /workspace/esp32s3-hello/target/xtensa-esp32s3-none-elf/release/esp32s3-hello /tmp/base.elf &&
     espflash flash --port $PORT /tmp/base.elf >/dev/null 2>&1"
out=$(monitor)
grep -q "Hello from ESP32-S3!" <<<"$out" || fail "restore"

echo "PASS: hardware loop green (base probes, overlay Howdy, counters, closure invariants)"
