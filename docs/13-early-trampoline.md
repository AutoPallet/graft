# 13. Early-trampoline & layout symbols

Status: design note. Not implemented. Triggered if you set
`GRAFT_ENTRY_SYMBOL=call_start_cpu0` (or any other early-startup
symbol) at base-build time and try an overlay link.

## What's broken

graft's standard configuration places its single trampoline at
`main`. That works because `main` runs *after* the SoC's startup
chain has already cleared bss, configured the flash MMU, installed
the vector table, run all `__init_array` constructors, and finished
ESP-IDF's task scheduler bringup. None of that early machinery is
in the closure for any code change rooted in `main` — closure walks
forward through call edges, and base's startup calls into `main`,
not the other way around.

Moving the trampoline earlier (to `call_start_cpu0`, the first
user-mode entry the ROM jumps to) makes everything that startup
touches part of the closure: bss-clear, flash MMU setup,
constructor walking, vector-table install, scheduler bringup, …
That's what we want — it's how init-code changes would actually be
picked up by an overlay.

But it also pulls into the closure (or at least to graft's
prune-time reloc resolver) a class of symbols whose addresses are
*layout-derived in overlay's link*: the same linker scripts both
base and overlay consume contain assignments like
`_bss_start = .;`, `_vector_table = ABSOLUTE(.);`,
`_instruction_reserved_start = ORIGIN(irom_seg);` etc. Each base
build produces values keyed to base's memory layout. Each overlay
build produces values keyed to *overlay's* layout — and graft
deliberately mutates `memory.x` (`irom_seg` ORIGIN/length, etc.) so
overlay code lands in the slack region. So the same scripts emit
*different* values for these symbols across base and overlay link.

When `call_start_cpu0` is in overlay's closure, its xtensa literal
pool (`.iram1.2.literal` in `cpu_start.c.obj`) carries relocs to:

- `_bss_start`, `_bss_end`, `_rtc_bss_start/_rtc_bss_end`,
  `_ext_ram_bss_start/_ext_ram_bss_end` — bss-clear ranges.
- `_instruction_reserved_start/_end`, `_rodata_reserved_start/_end`
  — flash MMU configuration ranges.
- `_vector_table` — vecbase install.

graft's overlay would, by default, produce a `call_start_cpu0` that
clears overlay's (mostly-empty) bss layout, configures the flash
MMU for overlay's (slack-region) instruction/rodata ranges, and
installs a vector table at overlay's vector address. Anything that
ran later — including the rest of base's code that shares the
running program's memory layout — would then operate against an
inconsistent view of memory and crash.

## What graft does today

graft's prune-time reloc resolver routes these names through
channel 3 (base.symtab snapshot) — the relocs get rewritten to a
per-target SHN_ABS anchor at *base's* address. That's the right
behavior in substance: overlay's `call_start_cpu0` should clear
*base's* bss, configure the MMU for *base's* IROM/DROM, install
*base's* vector table. The shared memory layout is base's.

The post-link verify, however, also forces each channel-3 name into
overlay's symtab via `-Wl,--undefined=<name>` (so verify has
something to compare against), which makes ld run the linker
script's `_bss_start = .;` assignment and produces overlay's
distinct value. The verify then sees `assumed=base_addr,
overlay_placed=overlay_addr` and bails.

For aggregator brackets (`__init_array_start/end` etc.), graft
already exempts these from verify on the same reasoning: relocs go
through the anchor at base's address; ld's separate resolution of
the original name is irrelevant.

The natural extension is to do the same for the layout-derived
script symbols. But just exempting them in verify isn't sufficient
— overlay's link script will still re-derive them, and any code in
overlay that *isn't* routed through graft's anchor (for instance,
if something in overlay's pruned input has its own reloc to
`_bss_start` that ld resolves through the script) will get the
wrong value silently.

## The intended fix

When graft mutates overlay's `memory.x` to retarget regions at
slack, *also* patch the linker script set to PROVIDE base's value
for layout-derived symbols whose addresses we want preserved.
Concretely, the `XtensaLayout`-mutation step (currently writes a
new `memory.x` and `sections.ld`) gains:

- A snapshot list, populated at base-build time alongside
  `.graft.symhash`/`.graft.manifest`, of `(name, address)` pairs
  for the symbols base's link assigned. This is the same data
  base.symtab already exposes (and graft already reads via
  `load_base_metadata`); we just consume the relevant subset
  here too.

- A generated linker fragment that does:

  ```ld
  PROVIDE(_bss_start    = 0x3fccf8f0);
  PROVIDE(_bss_end      = 0x3fcd1500);
  PROVIDE(_rtc_bss_start = 0x50000000);
  /* … */
  ```

  Inserted *before* the existing scripts via overlay's `-T` argv,
  so the PROVIDE wins over the script's later `_bss_start = .;`
  assignment. (The script assignments are unconditional, so we'd
  actually need to either prepend a comment-strip pass or use
  `--defsym=_bss_start=0x3fccf8f0` on overlay's link argv —
  `--defsym` overrides script assignments. That's the more
  robust path.)

- A curated catalog of which names get pinned. Likely:
  - `_bss_*`, `_rtc_bss_*`, `_ext_ram_bss_*` (bss layout)
  - `_data_*`, `_rtc_data_*` (data layout)
  - `_instruction_reserved_*`, `_rodata_reserved_*` (flash regions)
  - `_iram_text_*`, `_iram_data_*` (IRAM layout)
  - `__init_array_start/end` and aggregator brackets (already exempt
    in verify; the `--defsym` approach makes the exemption explicit
    rather than implicit).

The catalog stays in the xtensa-specific path (`overlay::xtensa::*`
or wherever the existing memory.x mutation lives) — these symbols
are esp-idf-specific. Cross-architecture infrastructure (the channel
3 anchor mechanism) stays generic.

## `_vector_table` is different — should be a synthetic node

`_vector_table` is structurally an aggregator bracket: it brackets
the start of `.iram0.vectors`, which is itself a merged output
(`KEEP(*(.WindowVectors.text))`, `KEEP(*(.Level2InterruptVector.text))`,
…). The right fit is in `synthetic::AGGREGATORS` as a new entry
analogous to `.init_array`:

```rust
Aggregator {
    id: ".iram0.vectors",
    contributor: Contributor::ExactOrDot(".iram0.vectors"),  // or pattern-match per-vector subsections
    bracket_symbols: &["_vector_table"],
}
```

Two complications. First, `.iram0.vectors` is *several* contributor
patterns (`.WindowVectors.text`, `.Level2InterruptVector.text`,
etc.), not a single `.iram0.vectors.*` family. The `Contributor`
predicate would need to enumerate them or grow an "any of these
names" variant. Second, only `_vector_table` exists as a bracket;
there's no matching `_vector_table_end`. The aggregator framework
currently assumes start/end pairs, so this would either need
single-bracket support or a synthesized `_vector_table_end` we
don't actually use.

Once `_vector_table` is an aggregator-bracket DefinedSymbol, it
flows through channel 1/2 like the init_array brackets — content
matched, no verify entry — and the `--defsym` PROVIDE pinning
above is unnecessary for it specifically. Aggregator content
matches between base and overlay (vectors don't change for typical
edits), so channel 2 hits, anchor at base's address. ✓

## Why we're not doing it today

Three layers of work, none small:

1. **`--defsym` injection for esp-idf layout symbols.** Easy
   mechanically (~30 lines in `XtensaLayout` mutation), but
   requires building the curated catalog and being confident it's
   complete. Missing a name produces a silent wrong-bss-clear at
   boot.

2. **Aggregator framework extension for `_vector_table`.** Either
   "any of these names" `Contributor` variant or single-bracket
   aggregator support, plus the catalog entry. ~50 lines.

3. **Scan-side discovery of archive members keep'd by linker
   script.** Currently scan demand-loads only via UND chain; ld's
   `KEEP(*(.init_array .init_array.*))` doesn't translate. Without
   this, even with the aggregator entry, scan won't see `.iram0.vectors`
   contributor sections inside archive members and won't build an
   aggregator node. This is the same upstream gap that makes
   `__init_array_start/end` route through channel 3 rather than
   channel 1/2. Bigger work — needs a parser for the relevant
   linker script subset, or ldproxy-mediated extraction of ld's
   actual KEEP-driven member-load decisions. Multiple hundred
   lines.

Until (3) is done, layered work helps but doesn't fully fix init
code change handling. The aggregator's content-aware invalidation
(needed for "did a constructor change" detection) requires scan to
see contributor sections.

## What graft does when this doc is relevant

If `verify_assumed_names` bails with `_bss_start` (or any of the
canonically-esp-idf layout symbol names) in the mismatch list,
graft prints a pointer to this doc as part of the diagnostic. The
heuristic name set is at `verify_assumed_names` in
`graft/src/overlay.rs`.
