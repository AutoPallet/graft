#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10,<3.13"
# dependencies = ["esptool==4.8.1"]
# ///
"""Sector-diff flasher for the esp dev loop.

`espflash flash` rewrites the whole app image even when a graft overlay
changed a few KB. This wrapper keeps the previously-flashed app image on
disk and, in ONE esptool serial session:

  1. gates on an on-chip MD5 of the app region (stub computes it
     chip-side) — proves the cache file matches what's actually in flash;
  2. writes only the 4K flash sectors that differ from the cache;
  3. re-MD5s the whole app region against the new image — the result is
     verified end-to-end regardless of any diff-logic bug;
  4. hard-resets the chip.

Any gate/verify mismatch or fast-path error falls back to a full
`espflash flash` (which also writes bootloader + partition table) and
re-seeds the cache. No chip-side state: the cache is just a file, and a
stale or deleted cache costs one full flash, never a wrong image.

Not covered by the gate: the bootloader/partition-table regions (only
the full path writes them; they only change when espflash itself does).
Use --full after an espflash upgrade.

Usage: flash-diff.py [--port /dev/ttyACM0] [--chip esp32s3] [--full] ELF
"""

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import time

APP_OFFSET = 0x10000  # espflash's default app partition offset
SECTOR = 4096


def log(msg):
    print(f"flash-diff: {msg}", flush=True)


def save_image(chip, elf, flash_size):
    """Build the app image exactly as `espflash flash` would write it.
    flash_size matters: espflash patches the detected size into image
    header byte 3, so an unsized save-image never matches the chip."""
    fd, path = tempfile.mkstemp(suffix=".bin", prefix="flashdiff-")
    os.close(fd)
    subprocess.run(
        ["espflash", "save-image", "--chip", chip, "--flash-size", flash_size,
         elf, path],
        check=True, capture_output=True,
    )
    with open(path, "rb") as f:
        data = f.read()
    os.unlink(path)
    return data


def detect_flash_size(port):
    """One esptool session to read the flash chip's size (e.g. '32mb')."""
    from esptool.cmds import detect_chip
    from esptool.cmds import detect_flash_size as esptool_detect

    chip = detect_chip(port=port)
    esp = chip.run_stub()
    try:
        size = esptool_detect(esp)
    finally:
        esp._port.close()
    if size is None:
        raise RuntimeError("esptool could not detect the flash size")
    return size.lower()


def full_flash(port, chip, elf, cache_path):
    """Cold path: detect flash size, let espflash write everything
    (bootloader + partition table + app), seed cache + size sidecar."""
    size = detect_flash_size(port)
    log(f"detected flash size: {size}")
    t = time.monotonic()
    subprocess.run(["espflash", "flash", "--port", port, elf], check=True,
                   capture_output=True)
    new_image = save_image(chip, elf, size)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "wb") as f:
        f.write(new_image)
    with open(cache_path + ".meta", "w") as f:
        f.write(size)
    log(f"full flash: {len(new_image)} bytes in {time.monotonic() - t:.1f}s")


def changed_runs(old, new):
    """Contiguous runs of 4K sectors where new differs from old."""
    nsec = (len(new) + SECTOR - 1) // SECTOR
    runs = []
    for s in range(nsec):
        a, b = s * SECTOR, (s + 1) * SECTOR
        if new[a:b] != old[a:b]:
            if runs and runs[-1][1] == s:
                runs[-1][1] = s + 1
            else:
                runs.append([s, s + 1])
    return runs


def diff_flash(port, cache, new):
    """One serial session: gate, write changed sectors, verify, reset.
    Returns False if the on-chip content doesn't match the cache."""
    from esptool.cmds import detect_chip, write_flash

    chip = detect_chip(port=port)
    esp = chip.run_stub()
    try:
        on_chip = esp.flash_md5sum(APP_OFFSET, len(cache))
        if on_chip != hashlib.md5(cache).hexdigest():
            log("gate: on-chip app region does not match cache — full flash")
            return False

        runs = changed_runs(cache, new)
        nsec = (len(new) + SECTOR - 1) // SECTOR
        total = sum(b - a for a, b in runs)
        # NOR flash programs 1->0 only; a sector whose new content never
        # flips a bit 0->1 could be written without erasing. The esptool
        # stub protocol has no no-erase write, so this is informational —
        # it shows what an 0xff-filled slack buys a smarter stub.
        prog_only = sum(
            1
            for a, b in runs
            for s in range(a, b)
            if all(
                o & n == n
                for o, n in zip(cache[s * SECTOR : (s + 1) * SECTOR],
                                new[s * SECTOR : (s + 1) * SECTOR])
            )
        )
        log(f"gate ok; {total}/{nsec} sectors changed in {len(runs)} runs "
            f"({prog_only} erase-skippable if stub supported it)")

        if runs:
            files = []
            addr_filename = []
            for a, b in runs:
                f = tempfile.NamedTemporaryFile(suffix=".bin", prefix="flashdiff-run-")
                f.write(new[a * SECTOR : b * SECTOR])
                f.flush()
                f.seek(0)
                files.append(f)
                addr_filename.append((APP_OFFSET + a * SECTOR, f))

            class Args:
                def __getattr__(self, _name):  # esptool probes many optional flags
                    return None

            args = Args()
            args.addr_filename = addr_filename
            args.compress = True
            args.no_compress = False
            # 'keep' = write our bytes verbatim, don't re-patch the image
            # header (a patched header would break the verify MD5 below)
            args.flash_size = "keep"
            args.flash_mode = "keep"
            args.flash_freq = "keep"
            args.erase_all = False
            args.encrypt = False
            args.no_stub = False
            args.verify = False  # superseded by the whole-region MD5 below
            write_flash(esp, args)
            for f in files:
                f.close()

        after = esp.flash_md5sum(APP_OFFSET, len(new))
        if after != hashlib.md5(new).hexdigest():
            log("post-write verify FAILED — falling back to full flash")
            return False
        esp.hard_reset()
        return True
    finally:
        esp._port.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("elf")
    ap.add_argument("--port", default=os.environ.get("GRAFT_HW_PORT", "/dev/ttyACM0"))
    ap.add_argument("--chip", default="esp32s3")
    ap.add_argument("--cache", default=None,
                    help="previously-flashed image (default: ~/.cache/graft-flash/<chip>-<port>.bin)")
    ap.add_argument("--full", action="store_true",
                    help="skip the diff path (e.g. after an espflash upgrade)")
    opts = ap.parse_args()

    cache_path = opts.cache or os.path.expanduser(
        f"~/.cache/graft-flash/{opts.chip}-{os.path.basename(opts.port)}.bin"
    )

    meta_path = cache_path + ".meta"
    t0 = time.monotonic()

    old = size = None
    if not opts.full and os.path.exists(cache_path) and os.path.exists(meta_path):
        with open(cache_path, "rb") as f:
            old = f.read()
        with open(meta_path) as f:
            size = f.read().strip()

    if old is None:
        if not opts.full:
            log(f"no cache at {cache_path} — full flash")
        full_flash(opts.port, opts.chip, opts.elf, cache_path)
    else:
        new = save_image(opts.chip, opts.elf, size)
        log(f"image: {len(new)} bytes ({os.path.basename(opts.elf)})")
        try:
            ok = diff_flash(opts.port, old, new)
        except Exception as e:
            log(f"diff path failed ({e}) — falling back to full flash")
            ok = False
        if ok:
            with open(cache_path, "wb") as f:
                f.write(new)
        else:
            full_flash(opts.port, opts.chip, opts.elf, cache_path)

    log(f"done in {time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    main()
