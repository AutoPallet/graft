# 06 — `graft`: wrapper design and test harnesses

Detailed-enough-to-critique design for the `graft` binary itself.
Companion to `05-esp32-adaptation.md` (the *what*); this doc is the
*how*, one level deeper.

## Shape

One binary, three entry surfaces:

1. **Linker shim** — cargo calls us via `.cargo/config.toml`'s
   `linker = "graft"`. rustc hands us the final link argv. Mode
   (`base` / `overlay` / passthrough) comes from the `GRAFT` env var.
2. **Subcommands** — `graft snapshot`, `graft combine`, `graft
   cache-info`, `graft clean`. User- or dev-driver-invoked. Disambiguated
   from linker mode by argv[1] matching a known subcommand name.
3. **Library** — the same crate exposes `graft::base`, `graft::overlay`,
   `graft::snapshot` so the integration test harness can drive the work
   in-process without forking.

Dispatch:

```rust
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if let Some(cmd) = args.get(1) {
        match cmd.as_str() {
            "snapshot"  => return subcommands::snapshot(&args[2..]),
            "combine"   => return subcommands::combine(&args[2..]),
            "cache-info"=> return subcommands::cache_info(&args[2..]),
            "clean"     => return subcommands::clean(&args[2..]),
            _ => {}
        }
    }
    match std::env::var("GRAFT").as_deref() {
        Ok("base")    => base::link(args),
        Ok("overlay") => overlay::link(args),
        _             => passthrough::link(args),
    }
}
```

Finding the real linker: `GRAFT_REAL_LD` env var in `.cargo/config.toml`
(defaults to `xtensa-esp-elf-ld`, or `ld` on x86). No magic — one
`exec`.

## Inputs

### Env

| Var | Required | Meaning |
|---|---|---|
| `GRAFT` | optional | `base`, `overlay`, or unset (passthrough) |
| `GRAFT_REAL_LD` | in config | Path to the real linker |
| `GRAFT_BASE_ELF` | overlay mode | Path to the base ELF whose metadata we load |
| `GRAFT_DEST` | overlay mode | `flash-partition`, `app-slack`, `sram` — affects packaging |
| `GRAFT_VERBOSE` | optional | `1` → log phase timings to stderr |

### Argv (linker modes)

Whatever rustc hands us — a complete linker invocation. We parse for:

- `-o <path>` — output path
- `.rcgu.o`, `.o` input files
- `.rlib` archives (extract members on demand)
- `-T <script>`, `-L <path>`, `-l <name>`
- Everything else is passed through unchanged

Parser is dumb string scanning, not a full linker arg grammar — we only
care about identifying inputs, the output, and being able to append our
own flags. We don't need to *understand* `-z noexecstack` or `--gc-sections`.

### Stdin

Unused.

### Outputs

- **stdout**: one line of JSON on success, machine-readable for the dev
  driver: `{"mode":"overlay","elf":"…","bin":"…","size":…,"abi":"…","closure":N}`.
- **stderr**: human-readable progress, phase timings if `GRAFT_VERBOSE=1`.
- **files**: the ELF at `-o`'s path (plus the overlay binary at a
  side-channel path for overlay mode).
- **exit code**: 0 success; nonzero + stderr message on failure.

## Base mode

```
graft::base::link(argv) →
    pre_scan_inputs(argv)     // 1
    real_link(argv)           // 2
    post_link_metadata()      // 3
    attach_sections()         // 4
    elf2image()               // 5 (optional)
```

### 1. Pre-scan inputs

Walk every `.rcgu.o`, `.o`, and every member of every `.rlib` in argv.
For each section (`SHT_PROGBITS` or `SHT_NOBITS` with `SHF_ALLOC`):

- Canonicalize relocations: replace target symbol indices with symbol
  names; sort by (offset, name).
- Compute `blake3(section_bytes || postcard(canon_relocs))`. This hash
  is the section's content identity, independent of link-time layout.
- Record `(obj_id, section_name, hash, relocs, defined_symbols)`.

Walk every symbol table entry: record `(symbol_name → (obj_id,
section_name, st_bind))`. `st_bind` matters for PROVIDE eligibility
later (only `STB_GLOBAL`/`STB_WEAK` can be PROVIDE'd into the overlay
link).

Time budget: hashing 10-15 MB of `.rcgu.o` with blake3 is ~50 ms on a
modern laptop. Parallel per file.

### 2. Real link

Append `--build-id=sha1` if not already present. Exec `GRAFT_REAL_LD`
with the argv. Wait for it; propagate nonzero exits.

### 3. Post-link metadata

Re-open the produced ELF. From standard fields:

- `.symtab` → `(name → st_value, st_size, st_bind)`.
- `NT_GNU_BUILD_ID` note → `BASE_ABI_VERSION` (20 bytes).
- Section headers → `(.text, .rodata, .bss, …)` address ranges, for
  overlay region placement.

Check for the "dropped symbols" set: symbols that existed in the
pre-scan `(symbol_name → defining_section)` but aren't in the final
`.symtab`. Those got GC'd, ICF-folded, or COMDAT-deduped. We still need
their bytes available for the overlay closure post-pass, so their
source sections stay in `.graft.objects`.

### 4. Attach sections

Construct the `.graft.*` metadata sections (schema below) and attach
via `object` crate (write a new ELF directly) or shell out to
`objcopy --add-section`. Direct-write is faster and gives us control
over section flags; use that. All sections `SHF_ALLOC=0` so they live
in the file but not in any `PT_LOAD` — `esptool elf2image` ignores
them, base.bin stays lean.

### 5. elf2image (optional)

If `GRAFT_DEST` indicates a flashable destination, invoke `esptool
elf2image` to produce `base.bin`. Otherwise stop at the ELF.

## Overlay mode

```
graft::overlay::link(argv) →
    parse_inputs(argv)            // 1
    load_base_metadata()          // 2
    hash_and_graph_overlay()      // 3
    compute_closure()             // 4
    assemble_consolidated_obj()   // 5
    generate_base_symbols_ld()    // 6
    generate_overlay_header()     // 7
    real_link(...)                // 8
    package()                     // 9
```

### 1. Parse inputs

Same as base-mode argv parsing: identify inputs, output path, scripts.

### 2. Load base metadata

Read `GRAFT_BASE_ELF`. Validate `.graft.manifest` version. Extract:

- `.graft.hashes` → `(obj_id, section_name) → hash`
- `.graft.symidx` → `symbol_name → (obj_id, section_name, st_bind,
  final_address)`
- `.graft.graph` → `(obj_id, section_name) → [reloc_target_symbol, …]`
- `.graft.objects` → archived bytes of every input object file, for
  re-emission of dropped-at-link-time sections
- `.graft.manifest.base_abi` → must match what the overlay records

Cache these in memory for the duration of the link.

### 3. Hash and graph the overlay inputs

Same pre-scan as base mode, but over this link's inputs. This gives
us the current `(section → hash)` to compare against base's cached
hashes, plus this link's forward-reloc graph.

Classification per section:
- **Unchanged**: same name appears in base with same hash.
- **Changed**: same name appears in base with different hash.
- **New**: name not in base at all.

### 4. Compute closure

Memoized forward-reloc walk from `main` (doc 05 § 167). `needs_overlay(s)`
= `changed/new` OR any reloc target needs overlay. Closure = memo's
truthy set.

Post-pass for dropped-at-link-time: for each closure reloc targeting a
symbol not in base's post-link `.symtab` and not in the closure, add
the defining section from `.graft.objects` to the closure. Iterate to
fixed point.

Also: for each closure reloc targeting a `STB_LOCAL` symbol in base,
pull the defining section into the closure (can't PROVIDE locals).

### 5. Assemble consolidated object

Build one synthetic `.o` file containing every closure section, with
relocations rewritten to point at internal section indices where the
target is also in the closure, and left pointing at external symbol
names where the target resolves via `base_symbols.ld`. `object` crate
writes it directly — no intermediate `ld -r`.

### 6. Generate `base_symbols.ld`

For each unique external symbol referenced by closure relocs, emit:
```
PROVIDE( symbol_name = 0xADDRESS );
```
Read addresses from `.graft.symidx`. Typical size: 100-500 entries.

### 7. Generate overlay header

One `OverlayHeader` struct (doc 05 § 79) encoded as bytes, emitted into
a synthesized section `.graft.header` at the start of the overlay
binary. Populated with:
- `magic`, `abi_version` (= `BASE_ABI_VERSION` from manifest)
- `entry` — defined by overlay source via `#[no_mangle] extern "C" fn
  overlay_entry()` or similar
- `bss_start`, `bss_end`, `data_load`, `data_start`, `data_end` —
  filled in by linker-provided `PROVIDE(__overlay_bss_start = .)` etc.
  in `overlay_layout.ld`

### 8. Real link

Exec `GRAFT_REAL_LD` with: the consolidated object, `-T
overlay_layout.ld`, `-T base_symbols.ld`, `-nostdlib`,
`--build-id=sha1`, output at a side-channel path (e.g.
`target/graft/overlay.elf`). Write a tiny stub ELF at argv's `-o`
path so cargo sees success.

### 9. Package

Per `GRAFT_DEST`:
- `flash-partition` / `app-slack` → `esptool elf2image` → `overlay.bin`.
- `sram` → raw byte dump of allocated sections at overlay-load address.

Emit the JSON status line on stdout.

## Passthrough mode

```rust
pub fn link(argv: Vec<String>) -> ExitCode {
    let real = env::var("GRAFT_REAL_LD").unwrap_or_else(|_| "ld".into());
    Command::new(real).args(&argv[1..]).exec().into()
}
```

Lets IDEs, `cargo check`, `build.rs` probes, and anyone running
without `GRAFT` set use cargo normally.

## Metadata in ELF sections

All stored with `SHF_ALLOC=0` / `SHT_PROGBITS`. None appear in any
`PT_LOAD`, so `esptool elf2image` ignores them and `base.bin` stays
lean. `objdump -h base.elf` lists them; `objdump -s -j .graft.manifest
base.elf` hex-dumps contents.

### `.graft.manifest` (~256 B)

Fixed-offset root record. `postcard`-serialized for stable binary layout.

```rust
#[derive(Serialize, Deserialize)]
struct GraftManifest {
    magic: [u8; 4],          // b"GRFT"
    version: u16,            // schema version, currently 1
    base_abi: [u8; 20],      // sha1 matching NT_GNU_BUILD_ID
    entry_symbol: String,    // "main" by convention
    toolchain_stamp: String, // rustc -Vv hash; prevents cross-toolchain overlays
    // Offsets/sizes are standard ELF section headers, not duplicated here.
}
```

### `.graft.objects` (~1-15 MB)

A thin-ar archive of every input `.rcgu.o` / `.o` / `.rlib` member that
contributed to base. Enables overlay mode to re-emit sections that got
dropped from base at link time (`--gc-sections`, COMDAT dedup, ICF,
weak-overridden). Indexed by `obj_id` — a monotonic u32 assigned at
pre-scan time.

### `.graft.hashes` (~500 KB)

Dense table of `(obj_id: u32, section_name_offset: u32, hash: [u8; 16])`.
`section_name_offset` indexes into a string pool in `.graft.strings`.
Sorted by `(obj_id, section_name)` for `O(log n)` lookup during overlay.

Truncated blake3 (first 16 bytes) is fine — we're comparing against
cached hashes of the same sections, not doing crypto.

### `.graft.symidx` (~200 KB)

`(symbol_name_offset: u32, obj_id: u32, section_name_offset: u32,
st_bind: u8, final_address: u64, st_size: u32)`. Sorted by
`symbol_name`. Covers every symbol that has a `.symtab` entry after
link, plus *surviving-in-some-form* symbols that were folded into
another (so ICF-folded addresses resolve correctly).

### `.graft.graph` (~1 MB)

For each section in `.graft.objects`: the list of `(offset:
u32, target_symbol_name_offset: u32, reloc_type: u16)` tuples. This is
what the forward-reloc walk consumes directly — no re-parsing of object
files needed for the common-case closure computation.

### `.graft.strings` (~200 KB)

Interned string pool: symbol names, section names, object file paths.
All other sections reference strings by offset into this pool.
Deterministic ordering (sort + dedup at build time) so byte-identical
inputs produce byte-identical `.graft.strings`.

### Why in-ELF rather than sidecars

- Single-artifact atomicity. You can't lose `base-syms.bin` while
  keeping `base.elf` — they're the same file.
- `base.elf` becomes distributable. Someone else can build overlays
  against it without the build directory.
- `objdump` and `readelf` can poke at it; nothing custom to inspect.
- Build-ID match is enforced by matching the same file's own ID.
- Cache directory layout stops being part of graft's ABI.

Cost: `base.elf` grows by ~10 MB on a non-trivial firmware. Host-only
artifact, never flashed — totally fine.

## Test harnesses

Three layers, distinct tooling per layer.

### Layer 1: unit tests in `graft/`

`cargo test` inside the crate. Pure functions, no filesystem or
subprocess.

- `hash::tests`: blake3 hash of known byte sequences is stable across
  runs and platforms. Canonical reloc serialization is order-
  invariant.
- `graph::tests`: forward-reloc walk on synthetic graphs
  (`Vec<(section, Vec<target>)>`) produces expected closures. Covers:
  no-change full leaf, changed-leaf bubbling to root, shared subtree
  hit once, cycle handling, post-pass fixed point.
- `metadata::tests`: manifest round-trips postcard cleanly; string
  pool deduplicates.
- `base_symbols_ld::tests`: generator emits syntactically valid ld
  script; only emits entries the closure references.

Target: ~300 tests, run in under a second, part of every CI push.

### Layer 2: fixture-driven integration tests in `tests/`

`cargo test --test fixtures`. Each fixture is a minimal workspace
under `tests/fixtures/<name>/`:

```
tests/fixtures/simple_leaf/
├── base/Cargo.toml
├── base/src/main.rs
├── base/src/lib.rs      # defines fn foo()
├── app/Cargo.toml
├── app/src/main.rs      # calls foo()
├── expected/
│   ├── initial_closure.txt
│   ├── after_edit_foo.txt    # closure after editing foo
│   └── after_edit_main.txt   # closure after editing main
```

Test driver: `graft::base::link` + `graft::overlay::link` invoked
in-process (no subprocess), with real `ld` shelled out to. Assertions:

- `initial_closure.txt` matches after first overlay build.
- Applying a scripted edit produces exactly `after_edit_*.txt`.
- Resulting overlay.elf parses and has the expected symbol set.
- Every PROVIDE in `base_symbols.ld` corresponds to a real address in
  base.elf's `.symtab`.

Fixtures exercise: leaf edit, mid-graph edit, main edit, dropped-
symbol (GC'd in base, pulled in by overlay), STB_LOCAL resolution,
weak symbol overridden, cycle in call graph.

Target: ~20 fixtures, each running in 1-3 seconds. Run on every CI
push.

### Layer 3: end-to-end on x86 (M0.5's primary deliverable)

A single fixture project under `e2e/x86/`, driven by `cargo xtask
e2e-x86`:

1. Build base (`GRAFT=base cargo build`).
2. Build overlay (`GRAFT=overlay cargo build`).
3. Run `graft combine` to produce `app.elf`.
4. `./app.elf`, capture stdout, diff against expected.
5. Edit a function, repeat 2-4, verify new behavior is live.
6. `gdb app.elf -batch -ex 'info functions edited_fn'` to verify
   debug-info points at overlay address.

Target: 5-10 scripted edit scenarios, runs in ~30 seconds end-to-end.
Runs nightly, not per-PR (too slow for every push).

### Layer 4 (deferred, M1+): on-device

A sacrificial ESP32-S3 on a fixed USB port. `cargo xtask e2e-device`:
flashes base, builds overlay, writes overlay, resets, reads serial
for an expected "overlay v1 ran" line. Flaky by nature (hardware,
serial timing); runs on-demand, not in CI.

## Open questions

- **`.rlib` handling.** `.rlib` is `ar` archive of `.rmeta` + `.o`s.
  Extract eagerly at pre-scan, or only on-demand when the closure
  pulls a member? Eager is simpler; lazy saves a few MB of memory.
  Punt: eager for v1, revisit if memory pressure appears.
- **Cross-link parallelism.** Hashing N object files is embarrassingly
  parallel; closure walk is serial. Start with single-threaded and
  profile.
- **`.graft.objects` dedup.** Many `.rcgu.o`s share template
  instantiations — content-addressed storage inside `.graft.objects`
  would shrink base.elf further. Probably not worth v1 complexity.
- **Deterministic builds.** Every artifact should be byte-identical
  for identical inputs. Postcard is deterministic; `ld` has
  `--sort-section=name` and `--hash-style=gnu` for stability; rustc
  has `-Z randomize-layout=no` (default). Audit once everything
  works.
- **Fixture golden-file churn.** Closure expected-outputs will shift
  with rustc versions. Store them alongside a `rustc_stamp` and
  regenerate in batch on rustc bumps.
