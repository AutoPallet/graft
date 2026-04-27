# 06 — `graft`: wrapper design and test harnesses

Detailed-enough-to-critique design for the `graft` binary itself.
Companion to `05-esp32-adaptation.md` (the *what*); this doc is the
*how*, one level deeper.

> **Reading note.** This is the original design; what's actually
> implemented diverged in several places — see
> [`08-implementation-status.md`](./08-implementation-status.md) for
> the deltas. The biggest ones for this doc:
>
> - **`GRAFT_DEST`** is gone — destination is hardcoded to slack
>   (option B). Overlay's link writes the combined ELF straight to
>   `-o`; there's no per-destination packaging step.
> - **Subcommands**: `snapshot` and `clean` are not implemented;
>   `combine` and `cache-info` are.
> - **stdout JSON metadata line** is not produced. rustc captures
>   linker stderr/stdout, so per-link telemetry instead lands as a
>   JSON line in `<output>.graft.log` (see `graft/src/telemetry.rs`).
> - **No stub ELF at `-o`** — overlay writes the *real* combined ELF
>   there. The standalone `overlay.elf` lives in graft's work_dir for
>   debugging.
> - **`OverlayHeader`** isn't generated; there's no runtime launcher.
> - **`exec`** is not used (we `Command::status` the real linker so
>   we can run combine afterward in the same process).
> - **xtensa overlay mode mutates `memory.x`** rather than emitting
>   its own `overlay_layout.ld`. The `arch::trampoline` boundary
>   (with its preserve-`entry` form on xtensa) is the only target-
>   specific code; everything else is class-aware (ELF32/64) and
>   target-neutral.
> - **xtensa combine path is splice, not append** (post-M1.k).
>   `combine_xtensa_splice` writes overlay's section bytes into
>   base's existing IROM/DROM sections at the slack file offset —
>   no new PT_LOADs, no PHT/SHT extension. The append-style code
>   (PHT rewrite, `add_overlay_section_headers`, overlap-trim)
>   only runs on x86 hosted now. See 08 § M1.k.

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

Pre-scan and real-link run concurrently — hashing every `.o` and
running the real linker touch the same inputs but are independent
operations. `ld` is the slow part; hashing hides under its runtime.

```
graft::base::link(argv):
    let (pre_scan_tx, ld_tx) = spawn2(
        || pre_scan_inputs(argv),          // thread A
        || exec_real_ld(argv + build_id),  // thread B
    );
    let pre = pre_scan_tx.join()?;
    ld_tx.join()?;                          // must succeed for the rest
    let post = post_link_metadata();
    attach_graft_sections(pre, post);
    if dest_is_flashable() { elf2image(); }
```

### Pre-scan (concurrent)

Walk every `.rcgu.o`, `.o`, and every member of every `.rlib` in argv.
For each section (`SHT_PROGBITS` or `SHT_NOBITS` with `SHF_ALLOC`):

- Canonicalize relocations: replace target symbol indices with symbol
  names; sort by (offset, name).
- Build the forward-reloc graph across all sections.
- Tarjan SCC on the graph. Compute the transitive hash per SCC in
  reverse-topological order of the SCC DAG:
  `trans_hash(scc) = blake3(concat(sorted(member.bytes ||
  postcard(canonical_relocs(member)))) || concat(sorted(
  trans_hash(successor_scc))))`. Every member section inherits the
  SCC's hash.
- Record `(symbol_name, trans_hash, address=0 placeholder, size=0,
  bind)` — address/size are filled in from `.symtab` after the real
  link completes.

Time budget: blake3 hashing 10-15 MB of `.rcgu.o` is ~50 ms on a
modern laptop; Tarjan + transitive propagation adds ~20 ms.
Parallelized across files for the initial byte hashing (the reloc
graph construction and SCC pass are serial but fast).
`xtensa-esp-elf-ld` on the same inputs is typically 500-2000 ms —
pre-scan hides entirely under ld's runtime, adding 0 ms to
wall-clock base build.

### Real link (concurrent)

Append `--build-id=sha1` if not already present. Exec `GRAFT_REAL_LD`
with the argv. Wait; propagate nonzero exits.

### Post-link metadata

Re-open the produced ELF. From standard fields:

- `.symtab` → `(name → st_value, st_size, st_bind)`.
- `NT_GNU_BUILD_ID` note → `BASE_ABI_VERSION` (20 bytes).
- Section headers → address ranges of `.text`, `.rodata`, `.bss`, for
  overlay-region placement.

Join with pre-scan output: for every symbol present in the final
`.symtab`, look up its pre-scan `trans_hash` and fill in the
`address` and `size` fields. Symbols that were dropped (GC'd,
ICF-folded, COMDAT-deduped, weakly overridden) don't appear in
`.symtab` and are simply omitted from the published table — overlay
will miss on them and include their defining section from its own
inputs.

**STB_LOCAL tagging.** For each entry joined into `.graft.symhash`,
if the pre-scan recorded the symbol as STB_LOCAL, tag it with
`tu = Some(tu_id)`. Globals get `tu = None`.

`tu_id` is a *structural* identifier for the translation unit —
stable across edits within that TU, so that overlay's rebuilt TU
shares a tu_id with base's original TU. Concrete derivation (pinned
in M0.25): `tu_id = blake3(stt_file_name)[:8]`, where `stt_file_name`
is the first `STT_FILE` symbol in the `.o`'s `.symtab`. rustc emits
one naming the CGU (e.g. `"66jii80ryvbi4xaubak5ll468"` — a 24-char
base36 CGU hash). The probe verified this is stable across pristine
re-runs, unrelated-crate additions, same-crate additions, and in-TU
body edits (4/4 TUs matched in every scenario). It changes correctly
when CGU partitioning changes (e.g. `codegen-units=1`) — those are
genuinely different TUs.

### Attach `.graft.*` sections

Build the two metadata sections (schema below) and write a new ELF
directly via the `object` crate — `object::read` to parse, then
`object::write::elf::Writer` to emit a new ELF with the original
sections copied plus our two appended. ~100 LOC. All metadata sections
`SHF_ALLOC=0` so they live in the file but not in any `PT_LOAD` —
`esptool elf2image` ignores them, base.bin stays lean. This is a post-
link pass today; optimizable later if profiling shows it matters.

### elf2image (optional)

If `GRAFT_DEST` indicates a flashable destination, invoke `esptool
elf2image` to produce `base.bin`. Otherwise stop at the ELF.

## Overlay mode

```
graft::overlay::link(argv) →
    parse_inputs(argv)            // 1
    load_base_metadata()          // 2
    hash_and_graph_overlay()      // 3
    compute_closure()             // 4
    prune_per_input_obj()         // 5
    generate_base_symbols_ld()    // 6
    generate_overlay_header()     // 7
    real_link(...)                // 8
    package()                     // 9
```

### 1. Parse inputs

Same as base-mode argv parsing: identify inputs, output path, scripts.

### 2. Load base metadata

Read `GRAFT_BASE_ELF`. Validate `.graft.manifest` version + the
toolchain stamp. Extract:

- `.graft.symhash` → `symbol_name → (trans_hash, address, size, bind)`
  for every symbol live in base's final `.symtab`.
- `.graft.manifest.base_abi` — must match what the overlay records.

### 3. Hash the overlay inputs

Same SCC + transitive-hash pass as base mode, over this link's inputs.
`trans_hash` per section; `symbol → defining_section` index built
along the way.

### 4. Compute closure

Reachability walk from `main` over the overlay's forward-reloc graph.
For each reachable section `s`:

- Pick any symbol defined in `s` and look it up in
  `base.symhash`. If base recorded a matching `trans_hash`, emit
  PROVIDE entries for every symbol `s` defines (addresses from
  base.symhash).
- Otherwise: add `s` to the closure.

That's the whole decision. Cycle handling lives in step 3 (SCC
condensation during hash computation); the walk itself is pure DFS
with a visited set.

After the walk: closure = all sections with no hash match. PROVIDE
entries = symbols in matched sections, plus any reloc target not
defined in the closure that `base.symhash` knows about (libc from
prebuilt `.a`, linker-provided, etc.). Base's bind doesn't matter —
PROVIDE defines a new global in the overlay's link regardless.

### 5. Prune each input `.o`

One pruned `.o` per source `.o`, each retaining only that file's
closure-member sections. Feed them all to `ld` as separate inputs —
easier to generate than a single consolidated object and it preserves
each input's local-symbol namespace, which matters for STB_LOCAL
disambiguation (below).

Per file:

- Read the source `.o`.
- Keep every section in the closure; drop the rest.
- For each surviving section's relocations, look at the target:
  - **Target is STB_GLOBAL:** leave the reloc as-is; it becomes an
    undefined external ref resolved by `base_symbols.ld` or by a
    surviving section in another pruned `.o`.
  - **Target is STB_LOCAL, *defining section also surviving in this
    file:*** leave as-is. ld resolves intra-file via the file's
    (trimmed) local symbol table.
  - **Target is STB_LOCAL, defining section *pruned* (or target is a
    base-only local we need to PROVIDE):** rename to
    `<name>@<tu_id>` with STB_GLOBAL bind. Matching PROVIDE is
    emitted in `base_symbols.ld`.
- Trim the `.symtab` to entries referenced by surviving sections or
  definitions within them.
- Write the pruned `.o`.

`tu_id` is the structural TU identifier (see base-mode post-link) —
stable across edits within the TU, so the same rebuilt TU keeps its
tu_id across base and overlay builds.

### 6. Generate `base_symbols.ld`

For each unique external symbol referenced by any pruned `.o`'s
unresolved relocs, emit:

```
PROVIDE( <name> = 0x<address> );                   /* global case */
PROVIDE( <name>@<tu_id> = 0x<address> );           /* local case */
```

Addresses come from `.graft.symhash`: globals match by `(name,
tu=None)`; locals by `(name, tu=Some(tu_id))`. Typical size: 100-500
entries.

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

Exec `GRAFT_REAL_LD` with: the pruned `.o`s, `-T
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

Two sections, both `SHF_ALLOC=0` / `SHT_PROGBITS`. Neither appears in
any `PT_LOAD`, so `esptool elf2image` ignores them and `base.bin`
stays lean. `objdump -h base.elf` lists them; `objdump -s -j
.graft.manifest base.elf` hex-dumps contents.

### `.graft.manifest` (~256 B)

Fixed-offset root record. `postcard`-serialized for stable binary layout.

```rust
#[derive(Serialize, Deserialize)]
struct GraftManifest {
    magic: [u8; 4],          // b"GRFT"
    version: u16,             // schema version, currently 1
    base_abi: [u8; 20],       // sha1 matching NT_GNU_BUILD_ID
    entry_symbol: String,     // "main" by convention
    toolchain_stamp: String,  // rustc -Vv hash; prevents cross-toolchain overlays
    overlay_region: (u64, u64), // link-time [start, end) address range
                                 // reserved for overlay (informational)
}
```

### `.graft.symhash` (~500 KB-2 MB)

One record per symbol live in base's final `.symtab`:

```rust
#[derive(Serialize, Deserialize)]
struct SymHashEntry {
    name: String,             // mangled symbol name, as in .symtab
    tu: Option<[u8; 8]>,      // None for STB_GLOBAL; Some(tu_id) for
                               // STB_LOCAL. tu_id is a *structural*
                               // translation-unit identifier that's
                               // stable across edits within a TU —
                               // i.e., overlay's rebuilt TU keeps the
                               // same tu_id as base's original.
                               // Derivation (pinned in M0.25):
                               // blake3(first STT_FILE symbol in the
                               // .o's .symtab)[:8].
    trans_hash: [u8; 16],     // truncated blake3 transitive hash of
                               // defining section (bytes +
                               // canonical relocs + SCC-successor
                               // trans_hashes). Sections in the same
                               // SCC share one trans_hash.
                               // All-zeros if sourced from a
                               // non-hashable input (prebuilt lib,
                               // linker-provided symbol).
    address: u64,             // st_value from .symtab
    size: u32,                // st_size from .symtab
}
```

Serialized as `Vec<SymHashEntry>` sorted by `(name, tu)` for binary
search. Typical size: ~10k symbols × ~80 B = ~800 KB. Truncated
blake3 is fine — we're comparing known sections against cached
hashes, not doing crypto.

Lookup during overlay mode:

- Overlay's pruned-`.o` reloc targeting a global: look up `(name,
  None)`. One entry, unambiguous.
- Overlay's pruned-`.o` reloc targeting a local whose defining
  section was pruned: look up `(name, Some(tu_id))` where `tu_id`
  is the structural id of the source `.o` that contained the
  reference. Because `tu_id` is derived from the TU's canonical
  name (not its contents), overlay's rebuilt TU shares a tu_id
  with base's original — even after in-TU edits — so the right
  local is picked.

Globals and locals coexist in the table; names don't need
disambiguation in storage because the tuple key is unique.

### Why in-ELF rather than sidecars

- Single-artifact atomicity. You can't lose `base-syms.bin` while
  keeping `base.elf` — they're the same file.
- `base.elf` becomes distributable. Someone else can build overlays
  against it without the build directory.
- `objdump` and `readelf` can poke at it; nothing custom to inspect.
- Build-ID match is enforced by matching the same file's own ID.
- Cache directory layout stops being part of graft's ABI.

Cost: ~1 MB of metadata on a non-trivial firmware. Negligible for a
host-only artifact that's never flashed.

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
  hit once, cycles (self-loop, 2-cycle, nested SCCs).
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
symbol (GC'd in base, pulled in by overlay), cross-binding reference
(overlay calls a base function that landed as STB_LOCAL), weak
symbol overridden, cycle in call graph.

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
  In overlay mode we need to hash sections in every member; extract
  eagerly or lazy-seek? Punt: eager for v1, revisit if memory
  pressure appears.
- **Parallelism beyond the ld/pre-scan overlap.** Byte hashing is
  embarrassingly parallel; Tarjan + the reverse-topological hash
  propagation are serial but fast. Reachability walk is serial.
  Start single-threaded on all of it and profile.
- **Deterministic builds.** Every artifact should be byte-identical
  for identical inputs. Postcard is deterministic; `ld` has
  `--sort-section=name` and `--hash-style=gnu` for stability; rustc
  has `-Z randomize-layout=no` (default). Audit once everything
  works.
- **Fixture golden-file churn.** Closure expected-outputs will shift
  with rustc versions. Store them alongside a `rustc_stamp` and
  regenerate in batch on rustc bumps.
