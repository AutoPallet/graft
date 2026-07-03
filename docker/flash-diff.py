#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10,<3.13"
# dependencies = ["esptool==4.8.1"]
# ///
"""Sector-diff flasher for the esp dev loop (replaces `espflash flash`).

State model: NO image blobs are kept. A flashed image is described by a
small MANIFEST — per-4K-sector SHA-256 list plus the first 256 bytes —
stored in ~/.cache/graft-flash/manifests/<tail-hash>.json, keyed by the
image's trailing 32 bytes (the app image's appended SHA-256, written
last by the ascending write protocol, so it doubles as a commit
record). The device is stateless, as in the OTA-diff design: the tool
walks the on-flash app image header to find the appended hash, looks up
that manifest, and diffs the new image's sector hashes against it.

One esptool serial session:

  1. probe the chip's flash size (~2ms) — espflash patches the detected
     size into the image headers, so the image must be built with it;
  2. build the full merged image (bootloader + partition table + app,
     `espflash save-image --merge`) exactly as espflash would flash it;
  3. header-walk the app partition on-flash to read the appended
     SHA-256; load the matching manifest; cross-check 256 bytes at 0;
  4. write the 4K sector runs whose hashes differ — ALL sectors when
     there is no matching manifest, the head check fails, or --full is
     given. The clean flash is just a diff against nothing; there is no
     separate full-flash code path, and bootloader/partition-table
     changes are ordinary diffs;
  5. hard-reset. The new manifest is stored only after a fully
     successful write, so a failed run takes the conservative path next
     time.

esptool MD5-verifies each region it writes chip-side (raises on
mismatch). Unwritten sectors are vouched for by the manifest lookup +
head probe alone — deliberate: a whole-region MD5 runs at ~320KB/s
chip-side (6.5s at 2MB). Accepted risk: an aborted or foreign flash
whose head and app-tail happen to match a stored manifest can leave
mixed content behind. Our own aborts converge: an abort before the
trailer sector leaves the old commit record on flash, so the next run
diffs against the OLD image's manifest and rewrites everything that
moved.

Usage: flash-diff.py [--port /dev/ttyACM0] [--chip esp32s3]
                     [--partition-table CSV] [--baud N] [--full]
                     [--seed] ELF

--seed computes and stores the manifest for ELF without touching the
device (for adopting an image known to be on-flash already).
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import tempfile
import time

SECTOR = 4096
HEAD_PROBE = 256
TAIL = 32


def log(msg):
    print(f"flash-diff: {msg}", flush=True)


def save_image(chip, elf, flash_size, partition_table=None):
    """Merged image (bootloader + partition table + app) at offset 0,
    byte-identical to what `espflash flash` would put there."""
    fd, path = tempfile.mkstemp(suffix=".bin", prefix="flashdiff-")
    os.close(fd)
    cmd = ["espflash", "save-image", "--chip", chip, "--flash-size", flash_size,
           "--merge", "--skip-padding"]
    if partition_table:
        cmd += ["--partition-table", partition_table]
    subprocess.run(
        cmd + [elf, path],
        check=True, capture_output=True,
    )
    with open(path, "rb") as f:
        data = f.read()
    os.unlink(path)
    return data


def manifest_of(img):
    return {
        "len": len(img),
        "head": img[:HEAD_PROBE].hex(),
        "tail": img[-TAIL:].hex(),
        "sectors": [
            hashlib.sha256(img[s : s + SECTOR]).hexdigest()
            for s in range(0, len(img), SECTOR)
        ],
    }


def walk_app_tail(esp, app_off):
    """Header-walk the on-flash app image; return its appended SHA-256
    (the manifest key). Raises on anything that isn't a hash-appended
    esp_image — callers treat that as 'unknown flash state'."""
    hdr = esp.read_flash(app_off, 24, None)
    magic, nseg, _mode, _sz, _entry = struct.unpack("<BBBBI", hdr[:8])
    if magic != 0xE9:
        raise ValueError(f"no app image magic at {app_off:#x} (got {magic:#04x})")
    if not 0 < nseg <= 16:
        raise ValueError(f"implausible segment count {nseg}")
    if hdr[23] != 1:
        raise ValueError("app image has no appended hash")
    pos = app_off + 24
    for _ in range(nseg):
        seg = esp.read_flash(pos, 8, None)
        _addr, dlen = struct.unpack("<II", seg)
        if dlen > 0x1000000:
            raise ValueError(f"implausible segment length {dlen:#x}")
        pos += 8 + dlen
    pos += 16 - (pos - app_off) % 16  # pad; checksum is the last pad byte
    return esp.read_flash(pos, TAIL, None)


def changed_runs(old_man, new_man):
    """Contiguous runs of 4K sectors whose hashes differ."""
    old = old_man["sectors"]
    new = new_man["sectors"]
    runs = []
    for s in range(len(new)):
        if s >= len(old) or new[s] != old[s]:
            if runs and runs[-1][1] == s:
                runs[-1][1] = s + 1
            else:
                runs.append([s, s + 1])
    return runs


def write_runs(esp, new, runs):
    from esptool.cmds import write_flash

    files = []
    addr_filename = []
    for a, b in runs:
        f = tempfile.NamedTemporaryFile(suffix=".bin", prefix="flashdiff-run-")
        f.write(new[a * SECTOR : b * SECTOR])
        f.flush()
        f.seek(0)
        files.append(f)
        addr_filename.append((a * SECTOR, f))

    class Args:
        def __getattr__(self, _name):  # esptool probes many optional flags
            return None

    args = Args()
    args.addr_filename = addr_filename
    args.compress = True
    args.no_compress = False
    # 'keep' = write our bytes verbatim; the image was already built
    # with the probed flash size, nothing should be re-patched
    args.flash_size = "keep"
    args.flash_mode = "keep"
    args.flash_freq = "keep"
    args.erase_all = False
    args.encrypt = False
    args.no_stub = False
    args.verify = False  # the stub already MD5-checks each written region
    write_flash(esp, args)
    for f in files:
        f.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("elf")
    ap.add_argument("--port", default=os.environ.get("GRAFT_HW_PORT", "/dev/ttyACM0"))
    ap.add_argument("--chip", default="esp32s3")
    ap.add_argument("--store", default=os.path.expanduser("~/.cache/graft-flash/manifests"),
                    help="manifest directory (per-sector hashes keyed by image tail hash)")
    ap.add_argument("--full", action="store_true",
                    help="rewrite every sector regardless of any manifest")
    ap.add_argument("--partition-table", default=None,
                    help="custom partition CSV (passed to espflash save-image)")
    ap.add_argument("--app-offset", type=lambda v: int(v, 0), default=0x10000,
                    help="app partition offset for the on-flash header walk")
    ap.add_argument("--baud", type=int, default=921600,
                    help="serial baud for the esptool session")
    ap.add_argument("--seed", action="store_true",
                    help="store ELF's manifest without touching the device "
                         "(--seed requires an explicit flash size via --flash-size)")
    ap.add_argument("--flash-size", default=None,
                    help="flash size for --seed (otherwise probed from the chip)")
    opts = ap.parse_args()

    os.makedirs(opts.store, exist_ok=True)
    t0 = time.monotonic()

    if opts.seed:
        if not opts.flash_size:
            ap.error("--seed requires --flash-size")
        new = save_image(opts.chip, opts.elf, opts.flash_size.lower(),
                         opts.partition_table)
        man = manifest_of(new)
        with open(os.path.join(opts.store, f"{man['tail']}.json"), "w") as f:
            json.dump(man, f)
        log(f"seeded manifest {man['tail'][:16]}… "
            f"({man['len']} bytes / {len(man['sectors'])} sectors)")
        return

    from esptool.cmds import detect_chip
    from esptool.cmds import detect_flash_size as esptool_detect

    chip = detect_chip(port=opts.port)
    esp = chip.run_stub()
    try:
        if opts.baud and opts.baud != esp._port.baudrate:
            esp.change_baud(opts.baud)
        size = esptool_detect(esp)
        if size is None:
            raise RuntimeError("esptool could not detect the flash size")
        size = size.lower()
        new = save_image(opts.chip, opts.elf, size, opts.partition_table)
        new_man = manifest_of(new)
        nsec = len(new_man["sectors"])
        log(f"image: {len(new)} bytes / {nsec} sectors, flash {size} "
            f"({os.path.basename(opts.elf)})")

        old_man, why = None, None
        if opts.full:
            why = "--full"
        else:
            try:
                tail = walk_app_tail(esp, opts.app_offset).hex()
                path = os.path.join(opts.store, f"{tail}.json")
                if not os.path.exists(path):
                    why = f"no manifest for on-flash image {tail[:16]}…"
                else:
                    with open(path) as f:
                        old_man = json.load(f)
                    head = esp.read_flash(0, HEAD_PROBE, None)
                    if head.hex() != old_man["head"]:
                        old_man, why = None, "head probe does not match manifest"
            except ValueError as e:
                why = f"header walk: {e}"

        if old_man is None:
            runs = [[0, nsec]]
            log(f"{why} — writing all {nsec} sectors")
        else:
            runs = changed_runs(old_man, new_man)
            total = sum(b - a for a, b in runs)
            log(f"manifest {old_man['tail'][:16]}… matched; "
                f"{total}/{nsec} sectors changed in {len(runs)} runs")

        if runs:
            write_runs(esp, new, runs)
        esp.hard_reset()
    finally:
        esp._port.close()

    with open(os.path.join(opts.store, f"{new_man['tail']}.json"), "w") as f:
        json.dump(new_man, f)
    log(f"done in {time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    main()
