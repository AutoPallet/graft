#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10,<3.13"
# dependencies = ["esptool==4.8.1"]
# ///
"""Sector-diff flasher for the esp dev loop.

`espflash flash` rewrites the whole app image even when a graft overlay
changed a few KB. This wrapper keeps the previously-flashed app image on
disk and, in ONE esptool serial session:

  1. probes the chip's flash size (espflash patches the detected size
     into image header byte 3, so the image must be built with it);
  2. gates on two 32-byte flash reads against the cache file: the image
     header + app descriptor (carries espflash's embedded ELF SHA-256)
     and the trailing appended image SHA-256. The trailer is written
     last by the ascending write protocol, so it doubles as a commit
     record: an interrupted earlier flash leaves it stale and the gate
     fails. ~2ms total vs ~700ms for a chip-side MD5 of the region.
  3. writes only the 4K flash sectors that differ from the cache;
  4. MD5s the whole app region chip-side against the new image — the
     result is verified end-to-end regardless of any gate/diff-logic
     hole (e.g. a foreign interrupted flash whose trailer happened to
     survive). ~700ms at 224KB; this is the piece to revisit (per-run
     verify) if images grow to MBs, where it approaches full-flash cost.
  5. hard-resets the chip.

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
PROBE = 32  # bytes per gate read


def log(msg):
    print(f"flash-diff: {msg}", flush=True)


def save_image(chip, elf, flash_size):
    """Build the app image exactly as `espflash flash` would write it
    for a chip with this flash size."""
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


def full_flash(port, elf, cache_path, new_image):
    """Cold path: espflash writes everything (bootloader + partition
    table + app), then the cache is re-seeded."""
    t = time.monotonic()
    subprocess.run(["espflash", "flash", "--port", port, elf], check=True,
                   capture_output=True)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "wb") as f:
        f.write(new_image)
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


def gate(esp, cache):
    """Two 32-byte probes: header+app-desc region and the trailing
    appended SHA-256 (written last => commit record)."""
    head = esp.read_flash(APP_OFFSET, 256, None)
    if head != cache[:256]:
        return False
    tail = esp.read_flash(APP_OFFSET + len(cache) - PROBE, PROBE, None)
    return tail == cache[-PROBE:]


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
    args.verify = False  # superseded by the whole-region MD5 after
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
                    help="skip the diff path (e.g. after an espflash upgrade)")
    opts = ap.parse_args()

    cache_path = opts.cache or os.path.expanduser(
        f"~/.cache/graft-flash/{opts.chip}-{os.path.basename(opts.port)}.bin"
    )
    t0 = time.monotonic()

    from esptool.cmds import detect_chip
    from esptool.cmds import detect_flash_size as esptool_detect

    chip = detect_chip(port=opts.port)
    esp = chip.run_stub()
    ok = False
    new = None
    try:
        size = esptool_detect(esp)
        if size is None:
            raise RuntimeError("esptool could not detect the flash size")
        size = size.lower()
        new = save_image(opts.chip, opts.elf, size)
        log(f"image: {len(new)} bytes, flash {size} ({os.path.basename(opts.elf)})")

        old = None
        if not opts.full and os.path.exists(cache_path):
            with open(cache_path, "rb") as f:
                old = f.read()

        if old is None:
            log("no cache — full flash" if not opts.full else "--full")
        elif not gate(esp, old):
            log("gate: on-chip image does not match cache — full flash")
        else:
            runs = changed_runs(old, new)
            nsec = (len(new) + SECTOR - 1) // SECTOR
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
            after = esp.flash_md5sum(APP_OFFSET, len(new))
            if after == hashlib.md5(new).hexdigest():
                esp.hard_reset()
                ok = True
            else:
                log("post-write verify FAILED — falling back to full flash")
    except Exception as e:
        log(f"diff path failed ({e}) — falling back to full flash")
    finally:
        esp._port.close()

    if ok:
        with open(cache_path, "wb") as f:
            f.write(new)
    elif new is not None:
        full_flash(opts.port, opts.elf, cache_path, new)
    else:
        # Couldn't even build the image (size probe / save-image died):
        # flash the safe way and drop the cache so the next run reseeds.
        subprocess.run(["espflash", "flash", "--port", opts.port, opts.elf],
                       check=True, capture_output=True)
        if os.path.exists(cache_path):
            os.unlink(cache_path)
        log("full flash (no image bytes for cache — reseed next run)")

    log(f"done in {time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    main()
