# 15 — "Normal" builds: PIE and dynamic linking

Status: design. Rev 2: the overlay link runs in PIC mode with
*section-defined* anchors, replacing rev 1's non-PIE overlay link +
`--emit-relocs` slot walk (rejected — see mechanism (a)). TLS rev 3:
SHF_TLS map sections (see mechanism (c)).

SUSPENSION NOTE (2026-06-10): PIE, dynamic linking, and the
rust-analyzer bench are suspended. Current focus: (1) the
section-anchor / map-object encoding implemented against the existing
ET_EXEC targets (x86 musl-static e2e + xtensa hw loop) with all tests
solid; (2) TLS map sections implemented and tested in the same pass
(references to unchanged base TLS resolve; changed/new TLS sections
bail until TLS slack exists). The `-pie` flip, RELATIVE merge, dynamic
machinery, and the bench resume from here later.

The question: today graft requires `x86_64-unknown-linux-musl` +
`crt-static` + `relocation-model=static`. What does it take to support
a *normal* `cargo build` — PIE, dynamically linked against glibc — and
specifically: what replaces SHN_ABS anchors for communicating
base-link results into the overlay link?

## What "normal" unbundles into

A default `cargo build` on x86_64-linux-gnu differs from our pinned
config in four ways:

1. **PIE**: output is ET_DYN, loaded at a random base. Link-time
   addresses are image offsets; runtime address = load bias + offset.
2. **Dynamic libc**: `printf`/`memcpy`/`stdout` live in `libc.so`,
   resolved at load time through PLT stubs and GOT slots.
3. **TLS**: same gap we already have (template offsets, not vaddrs) —
   but `std` uses TLS, so it stops being avoidable.
4. **PIC reloc vocabulary**: objects are compiled `-fPIC`-style, so
   prune sees GOTPCREL(X)/PLT32/TLS reloc families as the *common*
   case, not the exception.

## The core insight: base results are *image offsets*, provided as section-defined symbols

The splice design places overlay sections at fixed offsets *inside
base's image*. Under PIE the whole image moves together, so for any
PC-relative relocation (`S + A − P`) where both S and P are offsets in
the same image, the load bias cancels — and x86-64 code is almost
entirely PC-relative. Everything upstream — scan, identity, the
closure walk, the resolve cascade, the base table, the map oracle —
already operates in link-time offset space and doesn't change.

What changes is the anchor *encoding*. SHN_ABS is the wrong vehicle
under PIC because of what ABS means to ld: "this value never
relocates." ld correctly refuses PC-relative relocs against ABS
symbols in `-pie` links (S fixed, P moves), and — worse — writes
ABS64 slots with **no RELATIVE entry**, a silently unbiased pointer.
The ELF-native way to say "image-relative address" is a symbol
*defined in a section* placed at the right offset:

**Anchors become symbols in synthetic "base map" sections.** graft
(which already synthesizes input objects for slack) emits one
SHF_ALLOC NOBITS section per base PT_LOAD region, *split around the
slack carve-outs* so output sections never overlap, placed by the
overlay layout script at the region's link-time vaddr. Every anchor is
an ordinary symbol `(map section, offset)` — STB_GLOBAL +
**STV_HIDDEN** (global so pruned objects' UND references bind to it;
hidden so it stays out of dynsym and is non-preemptible, keeping
direct binding and GOTPCRELX relaxation behaving exactly as in a
normal executable link). Pruned objects emit anchors as UND
references; overlay.rs synthesizes the map object from the union of
dispositions. PLT stubs, GOT slots, vtables, functions — all of base's
content, *including linker-synthesized machinery*, is addressable this
way, because it is all just bytes at known offsets in base's image.

The overlay link then runs in PIC mode — `-pie -nostdlib
--no-dynamic-linker` — and ld does what it normally does for a PIE
executable:

- PC-relative refs to anchors → link-time constants (bias cancels).
- Absolute slots (`R_X86_64_64` in `.data.rel.ro`/`.data`) → ld writes
  the image offset AND emits `R_X86_64_RELATIVE` into the overlay's
  `.rela.dyn`.
- GOT slots ld materializes → RELATIVE entries likewise.

The overlay ET_DYN is still never executed — sections splice exactly
as before; its `.rela.dyn` is read as *metadata*: the authoritative
list of every slot that needs a load-bias fixup, produced by the
reference implementation. (Rev 1 linked the overlay as non-PIE ET_EXEC
and reconstructed this list with a graft-side `--emit-relocs` walk;
rejected because a slot class missed by the walk is a silently
unbiased pointer. Completeness must come from ld.)

SHN_ABS is not gone — it is demoted to what it actually means:
genuinely position-independent **constants**. With mechanism (c) also
map-based, its only remaining user is the channel-4 subset of names
base itself declares ABS *and* whose values lie outside the image
(esp32 ROM PROVIDEs — fixed silicon addresses). Note the trap this
split defuses: linker-script ABS symbols conflate true constants with
layout-derived snapshots (`_bss_start = .;`, `__init_array_start`) —
both read as ABS in base's symtab, but the latter are *positional* and
must be biased under PIE. Channel-4 anchors therefore classify per
name: value inside a base PT_LOAD → map symbol (biased); outside →
ABS constant (never biased). The old all-ABS encoding would have
silently left `__bss_start`-style anchors unbiased in a PIE. Absolute
relocs against ABS symbols are PIC-legal precisely because no fixup is
ever needed; encoding a constant as a section symbol would be the
mirror-image category error (ld would bias it).

Was ABS-for-addresses a design mistake? No — under non-PIE, address
and constant are *the same thing*, so ABS said exactly what was true
(and never caused a bug in that era; M1.t was an addend-combining
mistake, fixed within ABS-world). The distinction only comes into
existence when the image becomes movable. The rule going forward is
semantic: **anything positional — image-relative address or TLS
template offset → section-defined symbol in a map, on every target
including ET_EXEC ones** (one encoding, one pipeline; `-pie` is
per-target config); **true constant → ABS**.

The principle that generalizes the whole design: **graft provides
address-space facts (maps, slack) and inputs; ld synthesizes all
content; combine splices and verifies.** graft fabricates no
instructions anywhere — the entry trampoline jump written into base
remains the single target-specific byte sequence in the system.

Three mechanisms remain, and they are still the tier structure.

## Mechanism (a): consuming the overlay's RELATIVE relocs

The overlay link produces `.rela.dyn`; combine enforces and consumes
it:

- **Invariant: every entry must be `R_X86_64_RELATIVE`.** Anything
  else — GLOB_DAT, JUMP_SLOT (a reference escaped the resolve
  cascade), IRELATIVE (an overlay object defined an ifunc) — is a
  loud bail.
- **Invariant: in links with no DSO inputs** (Tier 0/A, and B/C
  before the new-import channel) **the overlay link produced no
  `.plt` and exports nothing to `.dynsym`** — every call target is
  defined (an overlay symbol or an anchor). With the new-import
  channel, ld-made import machinery is allowed but must be disjoint
  from base's import set — see mechanism (b).
- Because every allocatable overlay section was placed at its final
  image offset, `r_offset` and the addend are already final — no
  rewriting, just copying.
- **PIE tiers**: grow the loader-visible rela range and bump
  `DT_RELASZ`. Two implementations, because the loader follows the
  `DT_RELA` *pointer* (it never finds the table via section headers):
  (i) reserved contiguous **`.rela.dyn` slack** after base's table
  (same philosophy as text/rodata slack), or (ii) **copy-and-repoint**
  — copy base's table plus the appended entries into rodata slack and
  point `DT_RELA` there (no base-link reservation; costs a copy of
  base's table, which is large in big PIEs — choose per size).
  `DT_RELACOUNT` is left alone (a fast-path hint for the leading
  RELATIVE run; glibc's generic path handles RELATIVE entries after
  it).
- **Non-PIE base** (today's config): the load bias is permanently
  zero, so the entries are no-ops — combine verifies each `r_offset`
  lands in a spliced region and drops them. Same pipeline, one branch
  at the end.

This means the pipeline switch (section anchors + `-pie` overlay link
+ verify-and-drop) can land **now**, against the current musl-static
config, with identical output — de-risking it long before any PIE
tier ships. Tier A then only flips the combine branch and the base
config.

## Mechanism (b): dyn-resolved symbols → anchor base's *machinery*, not the symbol

For symbols living in shared libraries there is no image offset to
anchor. But base already built the runtime machinery for them, and the
combined binary keeps base's PT_DYNAMIC/dynsym/PLT/GOT byte-for-byte,
so the loader rebuilds identical runtime state. The overlay reuses it:

- **Calls** (`call printf` / PLT32): anchor at *base's PLT stub* —
  now just a section-anchor in the text map; stubs aren't special,
  they're bytes at known offsets. Recovery: parse base's `.rela.plt`
  (JUMP_SLOT entries name symbols; stub addresses follow in order).
- **Data access via GOT** (`mov stdout@GOTPCREL(%rip), %rax`): the
  instruction wants to *load a slot containing stdout's runtime
  address* — base already has exactly that slot (GLOB_DAT, fixed by
  the loader). Prune rewrites `R_X86_64_GOTPCREL(X)` →
  `R_X86_64_PC32` against an anchor at base's slot. Still mandatory:
  letting ld materialize a *fresh* slot for a libc symbol would
  require a symbolic dynreloc the combined binary can't host (and
  would trip the RELATIVE-only invariant — the failure is loud).
- **Address-taken functions** (`&printf`): base used a canonical PLT —
  its dynsym carries printf with st_value = stub offset. Anchor there;
  pointer equality with base's own `&printf` is preserved.
- **COPY-reloc'd data** (`environ` under non-PIE): physically lives in
  base's .bss at a real offset — channel 4 already handles it.
- **Interposition** (LD_PRELOAD malloc): inherited for free — overlay
  traffic flows through base's PLT/GOT, so the combined binary has
  *identical* interposition semantics to base.
- **New imports** (a symbol absent from base's dynamic machinery
  entirely — first use of `getenv` in an edit): **bail today**, but a
  designed extension with *no graft-fabricated code and no reserved
  PLT slots in base*. The overlay link simply links against **base's
  own DSO set** (recovered from DT_NEEDED / the original cmdline), so
  ld synthesizes the PLT stubs, GOT slots, and JUMP_SLOT/GLOB_DAT
  machinery natively — ISA knowledge stays in ld. The layout script
  places overlay's `.plt`/`.got.plt` into text/data slack; they splice
  like any other content. Combine appends the symbolic dynrelocs plus
  dynsym/dynstr/versym entries by copy-and-repoint (the loader follows
  DT_ pointers; no DT_GNU_HASH rebuild — hash tables index
  *definitions* for lookup by others, while an UND import is only
  reached via reloc `r_sym` indexes). Lazy binding is forgone:
  appended JUMP_SLOTs live in the DT_RELA range and resolve eagerly,
  so the stubs' lazy path is never taken. The invariants *sharpen*:
  (1) every ld-made import must be **disjoint from base's import
  set** — a stub for a symbol base already imports means the redirect
  channels above missed it (and would fork `&printf` identity against
  base's canonical stub) → bail; (2) symbolic dynrelocs may name only
  DSO-provided symbols (guaranteed — ld errors on truly-undefined
  names); (3) everything else RELATIVE. A new import from a *new*
  library needs a DT_NEEDED append (same copy-and-repoint on
  `.dynamic` + a PT_DYNAMIC phdr edit) — later. The channel must be
  driven by scan's demand-load model — "genuinely external to base",
  never "we failed to resolve it" (the lazy-archive lesson).

New base-side recovery surface: `.dynsym`, `.rela.plt`, `.rela.dyn`,
PLT stub layout — all standard, oracle-checkable structures. New
resolve channels slot alongside channel 4 (they are "names overlay's
scan never saw defined" by construction); the cascade ordering
invariant is untouched.

## Mechanism (c): TLS — a map for the TLS segment, like every other segment

`R_X86_64_TPOFF32` and friends are computed by ld from exactly three
facts: the symbol's template-relative offset, and the output PT_TLS's
memsz and align. All three are recoverable from base (TLS symbols'
st_values *are* template-relative offsets; PT_TLS gives geometry). So
the TLS segment gets precisely the treatment every PT_LOAD gets in
this design: **synthetic map sections reproducing its span at base's
vaddrs, split around the in-template slack carve-out, with anchor
symbols at the recovered offsets** — except these maps carry SHF_TLS,
so the overlay link builds an identical-geometry PT_TLS and computes
identical TP offsets itself.

- **Map shape**: a zero-filled PROGBITS map over base's `.tdata` span
  (file-backed, so initialized-before-zero ordering constraints hold),
  the slack hole left open, a NOBITS map over base's `.tbss` span —
  mirroring base's own filesz/memsz split. memsz and align match
  base's by construction; combine verifies overlay PT_TLS geometry ==
  base's and never splices the maps.
- **References to existing base TLS** bind to map symbols; ld computes
  tpoffs and runs its own relaxations (GD→IE→LE) — graft owns no
  tpoff arithmetic, no reloc rewriting, and no knowledge of TLS
  instruction sequences. TP offsets are load-bias-independent even in
  PIE, so TLS should contribute **zero dynamic relocs**; the one
  ld-version wrinkle is IE GOT slots in `-pie` links, which some lds
  fill statically and some cover with `R_X86_64_TPOFF64` — if the
  smoke test shows the latter, combine computes-and-drops them (one
  subtraction, guarded by the geometry-equality check). The current
  ET_EXEC config relaxes to LE and is trivially dynreloc-free.
- **New thread-locals stop being special**: they are ordinary
  `.tdata`/`.tbss` input sections the layout script places into the
  slack hole; ld assigns offsets and computes their tpoffs natively;
  splice writes their initializers into base's reserved template
  bytes. The end-anchoring constraint stands: tpoffs are end-anchored
  (variant 2), so the template can never *grow* at combine time —
  slack must be reserved inside base's template (and inside its
  filesz, for initialized vars) from day one. Keep it small — every
  thread copies filesz bytes at spawn.
- `__tls_get_addr`, if any GD sequence survives relaxation, is an
  ordinary external resolving through the normal channels (base's
  libc).
- base.rs's current "skip SHF_TLS symbols" exclusion becomes "recover
  into a separate template-offset-keyed table" — never mixed with the
  vaddr table. dlopen'd modules stay out of scope.

Rejected alternatives, in order:

- *rev 1, shadow TLS template* — rejected as a bespoke, layout-exact
  one-off. Half right: the map architecture is that idea in uniform
  form, where "layout-exact" collapses to a span, two geometry
  numbers, and symbol offsets — the same recovery done for every
  segment.
- *rev 2, constant-rewrite table* (`TPOFF32→32S` against ABS tpoff
  constants, `GOTTPOFF→PC32` at synthesized pool slots, GD/LD →
  synthesized `tls_index` pairs): tier-independent and
  instruction-untouched, but graft owns the tpoff math
  (divergence-from-ld risk), maintains a per-form rewrite table, and
  encodes TLS-sequence knowledge that belongs in ld. The map design
  needs none of it.

## Tiers, cheapest-first

**Tier 0 — pipeline switch, current config**: section-defined anchors
+ `-pie` overlay link + RELATIVE verify-and-drop, against today's
musl-static non-PIE base. Output is bit-equivalent in behavior; all
the new invariants (RELATIVE-only, no PLT, no dynsym exports) start
running immediately. De-risks everything below.

**Tier B — dynamic glibc, non-PIE** (`x86_64-unknown-linux-gnu` +
`-C relocation-model=static`, one rustflag): adds mechanism (b). No
combine changes beyond Tier 0 (bias is zero; entries still drop).
Cheapest tier that makes ordinary glibc projects work with a two-line
cargo config (ASLR loss is usually acceptable in dev builds —
debuggers disable it anyway).

**Tier A — static-PIE** (today's musl target *minus* the
`relocation-model=static` flag — rustc's musl default is static-pie):
flips combine's branch to the merge path: `.rela.dyn` slack +
DT_RELASZ bump. The existing e2e fixture converts by deleting one
flag.

**Tier C — the true `cargo build` default** (PIE + dynamic): B + A
composed, plus relro placement care (overlay GOT/`.data.rel.ro` land
in writable slack; acceptable to forgo RELRO for overlay pages
initially). TLS (c) is orthogonal and gates *edits whose closure
touches TLS-referencing code* in every tier — `std` uses TLS, so every
tier wants (c); it rides on the Tier 0 map machinery (SHF_TLS maps
work in ET_EXEC overlay links too), so it de-gaps the current
musl-static config immediately after Tier 0.

Embedded note: section anchors work in ET_EXEC links too, so the
anchor encoding unifies across targets; only the `-pie` flag is
per-target config. xtensa keeps its ET_EXEC overlay link until its
PIC dialect is smoke-tested (no reason to hurry — non-PIE is the
permanent reality there).

## What stays the same (the load-bearing list)

- scan / archive demand-load / closure walk / trans_hash identity:
  unchanged (object-level, layout-free).
- resolve cascade: same ordering invariant; gains channels for
  PLT-stub and GOT-slot anchors, the GOTPCREL→PC32 and TLS rewrites.
- base table + map oracle: unchanged (offset space).
- splice for sections: unchanged; combine *gains* the `.rela.dyn`
  verify/merge and (PIE tiers) DT_RELASZ surgery.
- The bail discipline: unknown reloc types, non-RELATIVE overlay
  dynrelocs, new dynamic imports, TLS forms outside the table — all
  loud bails, and with auto mode the product fallback is a full
  relink.

## Known risks / open questions

- `-pie -nostdlib --no-dynamic-linker` + our SECTIONS layout script
  needs a smoke test (Tier 0 exists to flush this out early).
- Script-placed SHF_TLS map sections + PT_TLS construction need the
  same smoke testing, including whether the local ld fills IE GOT
  slots statically in `-pie` or emits TPOFF64 (compute-and-drop path);
  the geometry-equality and zero-TLS-dynreloc checks guard the result.
- NOBITS base-map sections vs ld's output-section overlap checking:
  the per-segment maps are split around slack carve-outs so nothing
  overlaps; assert it.
- GOTPCRELX relaxation against section-defined hidden anchors should
  fire exactly as for normal local symbols — audit once (the M1.t
  lesson generalizes: GOT-flavored relocs are never transparent).
- IFUNC: overlay refs to base's ifunc-dispatched functions reuse
  base's already-resolved IRELATIVE slots via (b)'s GOT redirect;
  overlay-*defined* ifuncs trip the RELATIVE-only invariant → bail.
- `.eh_frame_hdr`: spliced overlay frames aren't in base's binary
  search table; panics/unwinds through overlay frames need the table
  rebuilt at combine time (hdr slack) — orthogonal to PIE but required
  for "normal" Rust (panic = unwind).
- Preemptible *base-exported* symbols (cdylib/dylib outputs): out of
  scope; executables only for now.
