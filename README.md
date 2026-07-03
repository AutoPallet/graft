# graft

Incremental **linking** for embedded and native Rust: relink only what an
edit changed, splice it into the previous binary, and flash only the
sectors that differ. No hot-patching, no runtime — the output is an
ordinary ELF that boots the normal way.

A full build links a **base** image once, recording where every input
section landed. After an edit, graft links only the transitive closure of
sections whose content changed — everything else resolves positionally
against the base — and byte-splices the result into reserved slack in the
base image. A sector-diff flasher (`docker/flash-diff.py`) then writes
only the changed 4KB sectors, identified through per-sector hash
manifests keyed by the image's appended SHA-256.

## Measured results

Large ESP32-S3 project (esp-idf + Rust std, ~2,900 input objects /
~173,000 input sections, 6.4MB app image), one-line edit loop on real
hardware:

|                    | full build            | graft edit loop  | win  |
|--------------------|-----------------------|------------------|------|
| link               | 135.9s                | 4.5–4.8s         | ~29× |
| flash              | 91.2s (1,564 sectors) | 2.7–3.2s (5–12 sectors) | ~30× |
| edit → running     | ~3m 45s               | 13–20s           | ~13× |

Typical overlay payload: 0.8–22KB spliced into a 6.4MB image. Of the
overlay link time, ~4.0s is input scanning/hashing — a persistent scan
cache is the next lever.

Native x86-64 (rust-analyzer, ~470k input sections): overlay relink
4.5s vs 138.5s full link, patched binary verified by execution.

Correctness is validated on-device by an abuse matrix over the edit
classes that historically produce *silent* incremental-link bugs —
changed static initializers with unchanged users, single-user edits
against base-resident statics, zero-init `.bss` twins (aliasing
canaries), string/rodata edits, function bodies reached only through
static function pointers, cross-crate edits — each checked against
computed expected values at boot.

## Why xtensa is hard

GNU ld *relaxes* xtensa code at link time (deletes longcall sequences,
narrows/widens instructions, drops literal-pool words), so "where did
this input byte land in the base" is not an offset calculation. graft
reconciles every relaxed section byte-for-byte against a finite transform
alphabet transcribed from binutils (`docs/16-relaxation-walk.md`),
refusing anything it cannot explain — 10,000/10,000 sections reconcile on
the reference corpus, and unexplained bytes force a re-emit rather than a
guess.

## Layout

- `graft/` — the linker wrapper (scan, closure, prune, relax walk, splice)
- `esp32s3-hello/` — bare-metal fixture + `docker/hw-test.sh` hardware loop
- `docker/flash-diff.py` — manifest-based sector-diff flasher
- `docs/` — design notes and post-mortems (start at `docs/README.md`)
