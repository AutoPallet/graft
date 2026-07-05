#!/usr/bin/env python3
# Superseded by docker/flash-diff.py (manifest-based sector diff).
# Kept for the M1-era measurement scripts that reference it.
"""
Diff two ESP32-S3 .img files at 4 KB SPI-flash sector granularity, then
range-write only the runs of changed sectors via `espflash write-bin`.

Usage:
    pageflash.py BASE.img NEW.img --port /dev/ttyACM0 \
                 [--partition-offset 0x10000] [--page-size 4096] [--dry-run]

The partition offset is the absolute flash address where the IMG starts
(default: 0x10000, the standard ESP-IDF factory partition). Page size is
the SPI flash sector size (default: 4096 / 0x1000); writes are aligned
to sector boundaries because espflash erases per sector.
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base", type=Path, help="reference .img already on flash")
    ap.add_argument("new", type=Path, help="new .img to be applied")
    ap.add_argument("--port", default="/dev/ttyACM0")
    ap.add_argument("--partition-offset", type=lambda s: int(s, 0), default=0x10000)
    ap.add_argument("--page-size", type=lambda s: int(s, 0), default=0x1000)
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="report change spans but skip espflash invocations",
    )
    args = ap.parse_args()

    base_bytes = pad_to_page(args.base.read_bytes(), args.page_size)
    new_bytes = pad_to_page(args.new.read_bytes(), args.page_size)

    # Equalize lengths by padding the shorter side with 0xFF (erased
    # flash). Differences in the tail then count as changed pages.
    if len(new_bytes) > len(base_bytes):
        base_bytes += b"\xff" * (len(new_bytes) - len(base_bytes))
    elif len(base_bytes) > len(new_bytes):
        new_bytes += b"\xff" * (len(base_bytes) - len(new_bytes))

    page_size = args.page_size
    total_pages = len(new_bytes) // page_size
    runs: list[tuple[int, bytes]] = []  # (flash_offset, bytes)
    i = 0
    while i < total_pages:
        if base_bytes[i * page_size : (i + 1) * page_size] == new_bytes[
            i * page_size : (i + 1) * page_size
        ]:
            i += 1
            continue
        # Start of a run; extend through all consecutive different pages.
        run_start = i
        while i < total_pages and base_bytes[
            i * page_size : (i + 1) * page_size
        ] != new_bytes[i * page_size : (i + 1) * page_size]:
            i += 1
        run_end = i
        flash_off = args.partition_offset + run_start * page_size
        chunk = new_bytes[run_start * page_size : run_end * page_size]
        runs.append((flash_off, chunk))

    pages_changed = sum(len(c) // page_size for _, c in runs)
    bytes_changed = sum(len(c) for _, c in runs)

    print(
        f"img: {len(new_bytes)} bytes / {total_pages} pages",
        f"diff: {pages_changed}/{total_pages} pages "
        f"({pages_changed / total_pages * 100:.1f}%), "
        f"{bytes_changed} bytes in {len(runs)} run(s)",
        sep="\n",
    )
    for off, chunk in runs:
        print(f"  run @ {off:#010x}  {len(chunk):>6d} bytes")

    if args.dry_run or not runs:
        return 0

    # espflash write-bin only takes one (offset, file) per call, but
    # `--before no-reset --after no-reset` keeps the device in the
    # stub bootloader between calls, skipping the connect/sync/stub-
    # load cycle on subsequent invocations. Per-call overhead drops
    # from ~0.9s to ~0.1s. Use default reset on the first call (clean
    # entry to bootloader) and `watchdog-reset` on the last (~0.5s
    # faster than hard-reset and still boots the new firmware);
    # everything in between uses no-reset on both ends.
    if not shutil.which("espflash"):
        print("espflash not on PATH; can't write", file=sys.stderr)
        return 1

    t0 = time.monotonic()
    bytes_written = 0
    with tempfile.TemporaryDirectory() as td:
        td_p = Path(td)
        for idx, (off, chunk) in enumerate(runs):
            blob = td_p / f"run_{idx}.bin"
            blob.write_bytes(chunk)
            cmd = ["espflash", "write-bin", "--port", args.port]
            is_first = idx == 0
            is_last = idx == len(runs) - 1
            if not is_first:
                cmd += ["--before", "no-reset"]
            cmd += ["--after", "no-reset" if not is_last else "watchdog-reset"]
            cmd += [hex(off), str(blob)]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                print(f"espflash failed for run @ {off:#010x}:", file=sys.stderr)
                print(r.stderr, file=sys.stderr)
                return r.returncode
            bytes_written += len(chunk)
    dt = time.monotonic() - t0
    print(
        f"wrote {bytes_written} bytes in {dt:.2f}s "
        f"({bytes_written / dt / 1024:.1f} KiB/s)"
    )
    return 0


def pad_to_page(data: bytes, page_size: int) -> bytes:
    rem = len(data) % page_size
    if rem == 0:
        return data
    return data + b"\xff" * (page_size - rem)


if __name__ == "__main__":
    raise SystemExit(main())
