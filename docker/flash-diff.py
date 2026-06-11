#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10,<3.13"
# dependencies = ["esptool==4.8.1"]
# ///
"""Sector-diff flasher for the esp dev loop (replaces `espflash flash`).

One esptool serial session:

  1. probe the chip's flash size (~2ms) — espflash patches the detected
     size into the image headers, so the image must be built with it;
  2. build the full merged image (bootloader + partition table + app,
     `espflash save-image --merge`) exactly as espflash would flash it;
  3. gate two flash reads against the cached last-flashed image: 256
     bytes at 0 (bootloader header + flash params) and the trailing 32
     bytes (the app image's appended SHA-256 — written last by the
     ascending write protocol, so it doubles as a commit record);
  4. write the changed 4K sectors — ALL sectors when the gate fails,
     the cache is missing, or --full is given. The clean flash is just
     a diff against nothing; there is no separate full-flash code path,
     and bootloader/partition-table changes are ordinary diffs;
  5. hard-reset. The cache reseeds only after a fully successful write,
     so a failed run takes the conservative path next time.

esptool MD5-verifies each region it writes chip-side (raises on
mismatch). Unwritten sectors are vouched for by the gate probes alone —
deliberate: a whole-region MD5 runs at ~320KB/s chip-side (6.5s at
2MB). Accepted risk: an aborted *foreign* flash can leave mixed
content behind matching begin/end probes. Our own aborts converge: an
abort before the trailer sector leaves the old commit record, so the
next run's diff-vs-cache rewrites everything that moved.

Usage: flash-diff.py [--port /dev/ttyACM0] [--chip esp32s3] [--full] ELF
"""

import argparse
import os
import subprocess
import tempfile
import time

SECTOR = 4096
HEAD_PROBE = 256
TAIL_PROBE = 32


def log(msg):
    print(f"flash-diff: {msg}", flush=True)


def save_image(chip, elf, flash_size):
    """Merged image (bootloader + partition table + app) at offset 0,
    byte-identical to what `espflash flash` would put there."""
    fd, path = tempfile.mkstemp(suffix=".bin", prefix="flashdiff-")
    os.close(fd)
    subprocess.run(
        ["espflash", "save-image", "--chip", chip, "--flash-size", flash_size,
         "--merge", "--skip-padding", elf, path],
        check=True, capture_output=True,
    )
    with open(path, "rb") as f:
        data = f.read()
    os.unlink(path)
    return data


def gate(esp, cache):
    head = esp.read_flash(0, HEAD_PROBE, None)
    if head != cache[:HEAD_PROBE]:
        return False
    tail = esp.read_flash(len(cache) - TAIL_PROBE, TAIL_PROBE, None)
    return tail == cache[-TAIL_PROBE:]


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
    ap.add_argument("--cache", default=None,
                    help="previously-flashed image (default: ~/.cache/graft-flash/<chip>-<port>.bin)")
    ap.add_argument("--full", action="store_true",
                    help="rewrite every sector regardless of the cache")
    opts = ap.parse_args()

    cache_path = opts.cache or os.path.expanduser(
        f"~/.cache/graft-flash/{opts.chip}-{os.path.basename(opts.port)}.bin"
    )
    t0 = time.monotonic()

    from esptool.cmds import detect_chip
    from esptool.cmds import detect_flash_size as esptool_detect

    chip = detect_chip(port=opts.port)
    esp = chip.run_stub()
    try:
        size = esptool_detect(esp)
        if size is None:
            raise RuntimeError("esptool could not detect the flash size")
        size = size.lower()
        new = save_image(opts.chip, opts.elf, size)
        nsec = (len(new) + SECTOR - 1) // SECTOR
        log(f"image: {len(new)} bytes / {nsec} sectors, flash {size} "
            f"({os.path.basename(opts.elf)})")

        old = None
        if not opts.full and os.path.exists(cache_path):
            with open(cache_path, "rb") as f:
                old = f.read()

        if opts.full:
            runs, why = [[0, nsec]], "--full"
        elif old is None:
            runs, why = [[0, nsec]], "no cache"
        elif not gate(esp, old):
            runs, why = [[0, nsec]], "gate: on-chip image does not match cache"
        else:
            runs, why = changed_runs(old, new), None

        if why:
            log(f"{why} — writing all {nsec} sectors")
        else:
            total = sum(b - a for a, b in runs)
            # NOR flash programs 1->0 only; a sector whose new content
            # never flips a bit 0->1 could skip the erase. The esptool
            # stub protocol has no no-erase write, so this is
            # informational — it shows what the 0xff slack fill buys a
            # smarter stub.
            prog_only = sum(
                1
                for a, b in runs
                for s in range(a, b)
                if all(
                    o & n == n
                    for o, n in zip(old[s * SECTOR : (s + 1) * SECTOR],
                                    new[s * SECTOR : (s + 1) * SECTOR])
                )
            )
            log(f"gate ok; {total}/{nsec} sectors changed in {len(runs)} runs "
                f"({prog_only} erase-skippable if stub supported it)")

        if runs:
            write_runs(esp, new, runs)
        esp.hard_reset()
    finally:
        esp._port.close()

    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "wb") as f:
        f.write(new)
    log(f"done in {time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    main()
