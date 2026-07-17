# graft

Graft is a **linker wrapper** that turns an existing linker into an incremental linker. It was primarily developed in order to dramatically accelerate the compile/link/flash/test cycle for complex Rust code targeting embedded platforms with complex vendor-provided linkers, but has also been tested against large x86 Rust projects.

In addition to incremental linking, graft also can perform identical-code-folding (ICF) for linkers that do not support doing so natively.

The produced binaries are designed to have small and contiguous changed regions from the base on which they are built, in order to allow efficient binary patching and flashing.

**maturity** Seems to work with some fairly complex tests on real hardware, but still under development

## Results

**rust-analyzer/x86/musl** (debug profile; 6,559 objects, 600,585 input
sections, 951 MB of linker inputs; incremental row = one-line edit)

| configuration                    | link time               | binary size                |
|----------------------------------|-------------------------|----------------------------|
| GNU ld 2.42                      | 18.7 s                  | 366.6 MB                   |
| graft+ld (base link, no ICF)     | 22.4 s                  | 372.3 MB                   |
| graft+ld (base link, ICF)        | 35.6 s                  | 357.0 MB (1.04× smaller)   |
| graft+ld (incremental build)     | **6.5 s (2.9× faster)** | 372.3 MB                   |

**large proprietary esp-rs codebase** (esp32s3 + esp-idf, 756 linker
inputs, 747 MB; flash times measured on hardware with the sector-diff
flasher — full flash writes 1,564 sectors, an incremental build 5–12)

| configuration                     | link time                 | flashed image                        | flash time                   |
|-----------------------------------|---------------------------|--------------------------------------|------------------------------|
| ldproxy (GNU ld)                  | 261.9 s                   | 6.2 MB                               | 91.2 s                       |
| graft+ldproxy (base link, no ICF) | 251.4 s                   | 6.3 MB                               | 91.2 s                       |
| graft+ldproxy (base link, ICF)    | 88.0 s (3.0× faster)      | 5.1 MB (1.2× smaller)                | —                            |
| graft+ldproxy (incremental build) | **8.3 s (31.6× faster)**  | 20–50 KB delta (**~250× smaller**)   | **2.7–3.2 s (~30× faster)**  |

## How it works

During an initial clean **base link**, graft forwards the arguments and inputs to the real linker
- graft also instructs the linker to reserve a configurable amount of blank space in the produced image for later use by functions modified during an overlay link
- In parallel with the real linker, graft computes and records the hashes of every input section (functions and data) as well as their dependency graph
- After the real linker finishes, graft adds an additional debugging section to the ELF file recording the hashes and dependency information[*](docs/how-it-works.md#the-identity-atom-trans_hash) for later use.
- Optionally, if ICF is enabled, graft rewrites linker input objects to deduplicate many identical functions.
- Graft additionally records the address where the real linker chose to put each input section.
- Graft then backs up a copy of the resulting ELF file

Later, after code changes have been made and new .o files are available, graft performs an **overlay link**:
- graft re-hashes the input files to determine which functions have changed (or refer to other functions that changed)
- graft produces new .o files containing only the updated functions (typically a small list)
- Any references to unmodified functions or data are replaced with the previously-recorded addresses of those functions decided during the base link
- graft instructs the real linker to place the modified functions in the previously-allocated blank space
- graft parses the output of the real linker, and "grafts" the modified functions, including the new main() function, into the blank space.
- graft replaces the original main() function with a stub that jumps to the new main function, leaving any modified functions from the base image present but unreachable.
- graft performs several checks to ensure that the resulting fused file is consistent and valid.

This process considers changes to functions, read-only data like strings, mutable data like static variables, and (for x86) thread-local variables.

In cases where the linker modifies the instructions in the linked code (*cough cough looking at you xtensa*) graft has an algorithm to reverse-engineer and resolve relocation targets correctly.

Slack is reserved once at base-link time and can never grow at combine time. The overlay link asserts its payload fits and bails (to a full relink under `auto`) if not.

## Usage

**For xtensa/esp32**

Add to `.cargo/config.toml` (working example:
[`esp32s3-hello/.cargo/config.toml`](esp32s3-hello/.cargo/config.toml)):

```toml
[target.xtensa-esp32s3-none-elf]
linker = "/path/to/graft"

[env]
GRAFT = "auto"                            # base link first, overlays after
GRAFT_REAL_LD = "xtensa-esp32s3-elf-gcc"  # the gcc driver, not bare ld
```

**For x86/linux** 
*todo*

## Limitations
Various things can cause a full re-link:
- Changes to (most) linker or compiler flags
- Too many modified functions for the available free space
- Changes to widely-used helper functions can trigger the above issue
- Modifications to constructors or other code that runs before main()

Other things are currently unsupported entirely
- Dynamically linked binaries (e.g. using glibc)
- Architectures other than x86 and Xtensa
- ICF for non-Rust code
- Certain complex linker scripts
- `--whole-archive` link lines (refused; use `GRAFT=passthrough`)

Known gaps in the combined output:
- Overlay code has no unwind tables (`.eh_frame` is dropped from
  overlays): a panic that unwinds through edited code aborts instead
  of unwinding. Irrelevant with `panic = "abort"` (the embedded
  targets); on hosted x86 builds panics still stop the program safely,
  but `catch_unwind` and drop cleanups don't run through overlay
  frames. Debug info for overlay code is likewise absent (base keeps
  its own symbols/DWARF; overlay code has symbols only), so name
  breakpoints on edited functions land on the stale base copy.
- The combined image inherits base's non-LOAD program headers
  (`PT_GNU_STACK` &c). An edit that changes such requirements — not
  something rustc-compiled code does — would not be reflected.


## Environment variables

| Variable | Effect |
|---|---|
| `GRAFT` | Mode: unset/`passthrough`, `auto`, `base`, `overlay`. |
| `GRAFT_REAL_LD` | Real linker graft execs (default `cc`; bare-metal sets e.g. `xtensa-esp32s3-elf-gcc`). |
| `GRAFT_BASE_ELF` | `overlay` mode: base ELF to prune against. |
| `GRAFT_REBASE` | `auto` mode: `1` forces a fresh base link, discarding the snapshot. |
| `GRAFT_ENTRY_SYMBOL` | Which function to replace with a jump to the overlay code (default `main`). |
| `GRAFT_SLACK_LEN` | Slack bytes the base link reserves for future overlays, as a comma-separated list of `region=len` pairs over regions `text`, `rodata`, `data`, `tls` (e.g. `"text=2M,tls=0"`). Lengths accept decimal, `0x` hex, and case-insensitive `K`/`M` suffixes. |
| `GRAFT_ICF` | `1` to enable identical-code folding (ICF): fold identical Rust code sections before the base link (default off). |
| `GRAFT_ICF_VERIFY` | Byte-level fold verifier (default on); `0` disables. |
| `GRAFT_ANCHOR_VERIFY` | Overlay-side byte-check of positional anchors against base.elf (default on); `0` disables. |
| `GRAFT_LOG` | Path for the per-link decision/telemetry log. |
| `GRAFT_DEBUG` | Comma-separated debug flags; unknown flag is a hard error. Flags: `preserve-icf-inputs`, `dump-graph=<path>` (dump the closure graph), `scan-timings` (per-phase scan timings to stderr), `icf-limit=<N>` (fold only the first N sorted ICF groups - for bisecting), `mismatch=<path>` (log nodes that missed a base-section match). |

