# 12 — Roborack3 demo: hot overlay flash on real hardware

A self-contained recipe for showing graft producing an overlay
binary that delivers a source change to a real ESP32-S3 (roborack3
fallback build). Hardware-validated end-to-end through wifi connect,
HTTP server registration, and runtime serial output verification.

## Prereqs

- `graft-roborack3` Docker container running (see
  [`docker/up.sh`](../docker)). The container has espflash, the
  xtensa toolchain, and a copy of the host's `target/x86_64-unknown-
  linux-musl/release/graft` mounted at
  `/workspaces/graft/target/...` so `linker = "graft"` resolves.
- Roborack3 board on `/dev/ttyACM0` (USB JTAG/serial).
- `~/roborack3` checked out clean on the host (worktrees should be
  visible inside the container at `/workspaces/roborack3`).

## One-shot setup

```sh
# Build graft for the container's musl runtime.
cd ~/projects/incremental_compilation
cargo build -p graft --release --target x86_64-unknown-linux-musl
```

## Step 1 — Build base, capture the snapshot

Base mode is graft's "first link": it runs the real linker
unmodified, then attaches `.graft.manifest` + `.graft.symhash`
sections to the output ELF. Those tell future overlay builds how to
find every symbol's address + transitive content hash.

```sh
ENTRY=_ZN6deploy9run_modes8fallback8fallback17hdd7b1a7033baf060E
GRAFT_BIN=/workspaces/graft/target/x86_64-unknown-linux-musl/release/graft

docker exec graft-roborack3 bash -c "
  cd /workspaces/roborack3 &&
  rm -rf target/xtensa-esp32s3-espidf/vehicle/deps/deploy-* &&
  CARGO_TARGET_XTENSA_ESP32S3_ESPIDF_LINKER=$GRAFT_BIN \
  GRAFT_REAL_LD=ldproxy \
  GRAFT=base \
  GRAFT_ENTRY_SYMBOL=$ENTRY \
  GRAFT_TEXT_SLACK_LEN=2000000 \
  GRAFT_RODATA_SLACK_LEN=400000 \
  GRAFT_DATA_SLACK_LEN=200000 \
  cargo bflash --no-default-features --features run_mode_fallback &&
  cp /workspaces/roborack3/target/xtensa-esp32s3-espidf/vehicle/deploy /tmp/base.elf
"
```

Why `fallback` instead of `main` as the entry symbol: the trampoline
gets installed at base's address of this symbol. Pointing it at
`main` collides with the ESP-IDF startup path (UART mutex still
half-initialized when overlay code first runs). `fallback` runs
after the runtime is fully up, so the mutation lands cleanly.

The slack reservations (`GRAFT_*_SLACK_LEN`) carve out unused address
ranges in base's text/rodata/data segments so overlay's content can
be spliced in-place at known vaddrs without colliding with base.

After this step, `/tmp/base.elf` (inside the container) is the
base ELF + `.graft.symhash` table. Flash it to verify base alone
works:

```sh
docker exec graft-roborack3 bash -c "
  cd /workspaces/roborack3 &&
  espflash flash --baud 1500000 --no-skip --no-verify --flash-size=16mb \
    --port /dev/ttyACM0 \
    --partition-table=deploy/partitions/partition_16mb.csv \
    --erase-parts otadata \
    target/xtensa-esp32s3-espidf/vehicle/deploy
"
```

Then watch boot for ~12s:

```sh
python3 ~/projects/incremental_compilation/scripts/capture.py "Connecting wifi" 1
```

You should see the standard ESP-IDF boot banner, `wifi_init`
diagnostics, then `deploy::nodes::wifi: Starting wifi...` and HTTP
server registration.

## Step 2 — Apply a visible mutation

Pick something whose effect you can see at runtime. Easiest: change
a serial log message in `wifi.rs`:

```sh
sed -i 's|Starting wifi\.\.\.|Starting wifi v2 EDITED for graft demo|' \
  ~/roborack3/deploy/src/nodes/wifi.rs
```

Verify the source actually changed:

```sh
grep "Starting wifi" ~/roborack3/deploy/src/nodes/wifi.rs
# Expected: info!("Starting wifi v2 EDITED for graft demo");
```

## Step 3 — Build the overlay against the captured base

Overlay mode reads the base's `.graft.symhash`, scans rustc's freshly
emitted `.o`s and the same archive set base saw, computes per-section
trans_hashes, and prunes everything whose hash matches base. Only
sections with new content end up in the output.

```sh
ENTRY=_ZN6deploy9run_modes8fallback8fallback17hdd7b1a7033baf060E
GRAFT_BIN=/workspaces/graft/target/x86_64-unknown-linux-musl/release/graft

docker exec graft-roborack3 bash -c "
  cd /workspaces/roborack3 &&
  rm -rf target/xtensa-esp32s3-espidf/vehicle/deps/deploy-* &&
  CARGO_TARGET_XTENSA_ESP32S3_ESPIDF_LINKER=$GRAFT_BIN \
  GRAFT_REAL_LD=ldproxy \
  GRAFT=overlay \
  GRAFT_BASE_ELF=/tmp/base.elf \
  GRAFT_ENTRY_SYMBOL=$ENTRY \
  GRAFT_LOG=/tmp/demo.graftlog \
  cargo bflash --no-default-features --features run_mode_fallback &&
  head -1 /tmp/demo.graftlog
"
```

Expected summary line shape:

```
graft overlay: base 10474 symhash · overlay 1418 objs / 117752 sections ·
  closure 92 sections · pruned 4 objs / 92 sections / 146 abs-rewrites ·
  combined 70655288 bytes (overlay payload 7616 @ 0x4216ebd0, 1 trampolines) ·
  scan 3.3s · closure 7.4ms · prune 3.7ms · link 21.3ms · combine 73.2ms · total 3.5s
```

Notice:
- `closure 92 sections` — only the chain reaching the changed
  function (`WifiNode::new` and its monomorphic dependents).
- `overlay payload 7616` — bytes of new code/data spliced into base.
- `combined 70655288` — same size as base.elf, because every byte
  fits in the slack regions reserved at base build time. No new
  PT_LOAD segments appended.
- `1 trampolines` — exactly one base-side jump rewritten (the entry
  symbol `fallback`), redirecting from base's old `fallback` address
  to overlay's new copy at `0x4216ebd0+offset`.
- `total 3.5s` — overlay link wall time, of which scan dominates
  (3.3s) and the actual ld invocation is ~20ms.

## Step 4 — Flash and verify the change ran

```sh
docker exec graft-roborack3 bash -c "
  cd /workspaces/roborack3 &&
  espflash flash --baud 1500000 --no-skip --no-verify --flash-size=16mb \
    --port /dev/ttyACM0 \
    --partition-table=deploy/partitions/partition_16mb.csv \
    --erase-parts otadata \
    target/xtensa-esp32s3-espidf/vehicle/deploy
"
```

Then capture serial:

```sh
python3 ~/projects/incremental_compilation/scripts/capture.py "v2 EDITED" 1
```

Expected output near the end:

```
I (3229) deploy::nodes::wifi: Starting wifi v2 EDITED for graft demo
```

That's the proof: the device is running overlay's mutated
`WifiNode::new`, which prints the new string. The full system after
the trampoline (HTTP server, gamepad WebSocket, etc.) keeps working
because every cross-section reference either (a) resolves internally
in overlay's pruned objects to the new copy or (b) gets SHN_ABS-
encoded to base's address for unchanged code.

## Step 5 — Clean up

```sh
cd ~/roborack3 && git checkout -- deploy/src/nodes/wifi.rs
```

(Optional: re-flash base alone to leave the device running unmodified
firmware, same recipe as Step 1's flash command.)

## Troubleshooting

**Boot hangs at `main_task: Calling app_main()` and never reaches
`Connecting wifi`.** Most likely: a re-emitted runtime singleton
(stdio mutex, allocator state). Try a different `GRAFT_ENTRY_SYMBOL`
deeper in the call chain — anything past where stdio is fully
initialized.

**Build fails with `can't resolve <name> against base`.** graft
couldn't find a base address for that name. If `<name>` is a wrap
target (`-Wl,--wrap=...`), it should have been auto-detected — check
that the link argv graft sees has the wrap flag. If `<name>` is an
anonymous-section symbol with `<cgu-fp>` pattern, you've hit the
deferred [M1.m.2 anon-content-match path](08-implementation-status.md);
that mutation can't be overlay'd until that work lands.

**Combined ELF is much bigger than base ELF.** Should NOT happen
with `-nostartfiles` — overlay content lives in slack regions of
existing PT_LOADs. If you see appended PT_LOADs (different
`combined` size from `base.elf`), check that `-nostartfiles` is in
the overlay link argv.

## Reference: Mutation matrix runner

For automated runs across the 4×2 mutation matrix, see
[`docs/10-mutation-experiments.md`](10-mutation-experiments.md) and
the `/tmp/run_experiments.py` runner.
