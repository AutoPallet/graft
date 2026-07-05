# 14 — Identity granularity: nodes, sections, symbols

Status: design note (2026-06-10, rev 3). Motivated by the open xtensa
overlay bug (see `docs/worklogs/08` § "Open: classify-vs-resolve inconsistency"
and `CLAUDE.md`).

> **Rev history.** Rev 1 proposed per-*symbol* nodes — retracted as
> unsound (relocless intra-section jumps). Rev 2 proposed a 3-part
> resolution-consistency fix keyed on per-symbol symhashes. Rev 3
> (current) replaces that with a single per-*section* address table and
> *positional* resolution, which subsumes the rev-2 fixes and lets the
> entire per-symbol `symhash` layer be deleted.

## TL;DR

A node is **"what the linker can ship"** = a whole section (relocless
intra-section jumps make any finer atom unsound; see the theorem below).
`SHF_STRINGS` pools are the one licensed exception.

Base metadata collapses to **one table**: `trans_hash → section base
address`, one entry per retained section. Everything resolves
**positionally**:

- ref to symbol `foo` → `base_section_addr[foo.node.trans_hash] +
  foo.offset_in_section`
- `<section> + addend` → `base_section_addr[node.trans_hash] + addend`
- classify "Provided" → `base_section_addr` contains `node.trans_hash`

This **dissolves the weak-duplication bug** with no consistency rules,
deletes the `symhash` (name‖trans_hash) concept, the surrogate
symbol-search, and `build_symhash`'s ld-resolution bookkeeping. Names
re-enter only as a collision tiebreaker (below).

## Why a node is a whole section (the relocless-jump theorem)

The assembler emits a reference without a relocation only when it already
knows the target's offset — which it does **only within its own
section** (it cannot know where the linker will place other sections).
Therefore:

- **Every cross-section reference carries a relocation.**
- **Every relocless reference is intra-section** (local branches, loops,
  tail-falls into a sibling packed in the same section, multi-entry asm —
  all common in IRAM `.rwtext`).

So a **whole section**'s behavior is fully determined by *its own bytes* +
*its relocs' targets*, which is exactly what `trans_hash` captures —
whole-section identity is sound. A **sub-section slice is not**: a
relocless backwards jump can cross a slice boundary, so you'd hash a
function as unchanged while a neighbor it falls into changed underneath
it, and emit it as Provided-by-base when its behavior actually drifted.
That is the silent-failure direction.

### The one license to go sub-section

A node may be finer than a section only when **both** hold: (1) ld itself
ships at that granularity, and (2) the sub-units have no relocless
cross-references. `SHF_MERGE|SHF_STRINGS` passes both (ld dedups per
NUL-terminated string; character data never branches), so the per-string
split is sound; refs into a pool arrive as `<section>+addend` and resolve
to the specific string node. Code passes neither — **never split code.**

### Practical upshot for incrementality

If any byte of a coarse section changes, the whole section is re-shipped
and everything referencing it cascades into the closure. We accept this:
correctness first. The lever for finer incrementality is **more
sections** (`-ffunction-sections`, or splitting a `#[link_section]`
blob) — the user's choice, not something graft can safely synthesize
from a section the compiler chose to pack.

## The single-table design

### Base side: `trans_hash → section base address`

For every retained input section (node), record its base virtual
address. base.elf's section headers only give the *merged output*
section (e.g. one `.rwtext` for all CGUs), not per-input sub-offsets, so
the address is recovered per node. Source of the address, in preference
order:

1. **Back-compute from the node's own symbols.** For each symbol the node
   defines that base.elf resolves, `candidate_base = final_addr −
   st_value`. Symbols genuinely in *this* copy agree on one base; a weak
   global ld resolved to a *different* copy is an outlier. Take the
   **majority** candidate (prefer locals — they are never cross-resolved,
   so a single local is authoritative). This needs only the scan + base's
   symtab — no `.o` mutation, no map parsing.
2. **`-Map` fallback** (TBD) for sections whose symbols are *all*
   cross-resolved weaks or which have no named symbol at all (retained
   purely via an `STT_SECTION` reference). The linker map lists every
   input section → placed address directly. Format-fragile, so a fallback
   only.

**`-Map` as test oracle (required).** Independent of whether `-Map` is
used at runtime, a unit/integration test links a fixture with
`-Map=…`, parses the input-section → address lines, and asserts the
back-computed `trans_hash → address` table agrees with the map for every
section. This turns the linker's own placement record into ground truth
for address recovery, catching majority-vote mistakes (outlier picked,
off-by-st_value, wrong section matched) that would otherwise be silent.
Keep it green as coverage methods evolve.

For the first implementation, sections that resolve via neither are
simply absent from the table; an overlay reference to one bails
(fail-loud), per the user's "every retained section is named by *some*
symbol, else we don't care about it" theory. We harden coverage
(majority-vote, then `-Map`) until it's bulletproof.

### Overlay side: positional resolution

The scan already gives, per defined symbol, its node (→ `trans_hash`) and
`st_value` (= offset within the section). prune resolves a reference by
looking up the target's `trans_hash` in `base_section_addr` and adding
the offset/addend. No `symhash`, no name in the hot path.

The weak-duplication bug is **gone by construction**: `foo` in CGU-A's
`.rwtext` (`th_A`) and CGU-B's (`th_B`) are different keys; base records
both (it retained both sections); whichever node overlay resolves `foo`
through lands in a byte-identical copy of `foo` — and weak symbols are
interchangeable by definition, so any copy is correct. base and overlay
never have to agree on a canonical copy.

### Where names still belong: the collision tiebreaker

`trans_hash` excludes names (content+deps only). Two *distinct* symbols
with byte-identical sections + identical successors therefore share a
`trans_hash`. If base placed them at **distinct** addresses (no ICF) and
the program **observes** the address difference (address-taken identity
compare), positional resolution could pick the other copy. This is
exactly the ICF-unsafe boundary.

Handling: base detects `trans_hash` collisions with differing addresses
and marks them **ambiguous**. A named reference whose `trans_hash` is
ambiguous disambiguates via `base_symtab` (name → address from base.elf)
+ the existing post-link verify; a `<section>+addend` reference into an
ambiguous `trans_hash` (no name to disambiguate) bails. For calls/jumps
the copies are byte-identical so any is sound; the tiebreaker only
matters for observed address identity. This is the *whole* residual role
of names — a narrow tiebreaker, not a general fallback path.

## What gets deleted

- `metadata::SymHashEntry` / `.graft.symhash` → `SectionEntry { trans_hash,
  address }` / `.graft.sections`.
- `hash::symhash_of` and the `symhash` concept (closure/classify/prune
  all key on `trans_hash`). `stable_name_part` survives only if still
  needed by `ContentResolver` canonicalization.
- `base::build_symhash`'s ld-resolution bookkeeping (Global>Weak,
  multiple-def, first-weak) — replaced by per-node address recovery.
- `overlay::OverlaySymhashes` globals/locals/locals_any_tu → a simpler
  `name → (trans_hash, offset)` map.
- `prune::compute_section_base_vaddr`'s surrogate symbol-search → a
  direct `base_section_addr[trans_hash]` lookup.
- `BaseResolver`'s symhash maps → the section table + offset map.

## Linker dedup: N nodes → one address (valid, already handled)

Two distinct nodes resolving to the same base address is the *good*
direction (ICF, string merge). Under the section table they share a
`trans_hash` and one entry — sound, since they're interchangeable. (This
is the benign side of the collision case above.)

## Mutable state has nominal identity (rev 4)

The pure-content design above has a hole that hardware execution exposed
(the M2 xtensa call-to-0): **content identity is undefined for sections
whose bytes don't define them.** Every `.bss` section is byte-less
(NOBITS); every zero-init `.data` section is byte-identical to every
other one of the same shape. Under pure content keying,
`esp32s3_hello::TICK_COUNTER`, `ATOMIC_TICK`, and `esp_println`'s
`TIMED_OUT` all collapsed onto one trans_hash and resolved to one base
address (an empty `.data.wifi`), and `esp_println::LOCK` silently
aliased `ESP_HAL_LOCK`. On xtensa nearly every static access is an
`STT_SECTION` literal, so the name-pinning channel (2a) never got a
chance.

The rule mirrors ld, which content-folds read-only data and code but
never writable sections: a section is **content-addressable** iff it has
bytes and is read-only or executable (`SectionInfo::content_addressable`;
RAM-resident code like `.rwtext` stays content-addressed — code is
immutable content regardless of segment writability). Everything else —
mutable data, NOBITS, zero-size — gets a **nominal salt** folded into its
leaf hash: the sorted (symbol name, st_value) pairs it defines, with
rustc's `.llvm.<id>` internal-linkage suffix stripped so CGU
repartitioning doesn't churn the identity of an unchanged static (which
would silently *duplicate* its state into the overlay). One table, no
new channels; names enter exactly where content-dedup is impossible.

Two corollary bails in prune (both pinned in `prune_channels`):
- a named ref to an *ambiguous mutable* hash that `base_symtab` can't
  pin → bail (a representative copy would alias distinct variables);
- an `STT_SECTION` ref into an ambiguous mutable hash → bail (no name
  to pin with). The representative shortcut survives only for
  read-only/exec content, where any byte-identical copy reads the same.

The salt also flows into `ContentResolver`'s fingerprints — otherwise a
referrer that swaps which of two same-content statics each instruction
touches would produce a byte-identical canonical reloc list and an
identical edge *set*: an invisible change.

## A node's trans_hash is per-node, not per-SCC (rev 4)

The second hardware-exposed hole: SCC members shared one trans_hash, but
**same trans_hash must imply "same content at a recoverable address" and
SCC sharing breaks that**. On xtensa, code and its literal pool reference
each other (`.rwtext` l32r's into `.rwtext.literal`; the pool holds
addresses of handlers back in `.rwtext`), so they *always* form a cycle.
Both sections inherited the SCC's hash; base's address recovery saw one
hash at two addresses, flagged it ambiguous, and the "representative"
(smallest) copy resolved `ram_resident_step` into the middle of the
literal pool — a wild jump.

Fix: the per-node hash is `blake3(scc_hash ‖ member_input_hash)[:16]`.
Any transitive change still changes the SCC hash and therefore every
member's value (change detection is preserved); genuinely identical
singleton sections still collide (dedup is preserved); but distinct
members of one cycle map to distinct table entries with well-defined
addresses. After this, "ambiguous" really does mean byte-identical
interchangeable copies.

## Resolve once (rev 5)

The scan resolves every reloc exactly once (`graph::build` records
`reloc_targets`, with `--wrap` renaming and the cross-TU local fallback
applied) and one cascade — `resolve::Resolver::dispose` — turns those
resolutions into prune emissions. Prune is a dumb rewriter: it wires
intra-object internal targets (only it sees the object's symbol
indexes) and emits what dispose says. Hash edges, the closure walk, and
disposition consume the SAME resolution, structurally eliminating the
"classify vs resolve disagree" bug class. Channel 1 is node-keyed (a
content twin in the closure can't fool it).

Corollary fixed on the way (hardware caught it): section NAMES repeat
within one object (two `.rwtext`s in the esp32s3 rcgu), so any
name-keyed section lookup picks an arbitrary copy. `CanonicalReloc`
now carries the physical `target_section` index and every consumer
keys on it; the index is cleared before hashing (it shifts under CGU
repartition) — the canonical content fingerprint remains the
hash-stable identity. Schema v5.

## Base-time invariant checks

- **STB_LOCAL unanimity**: a node's locals are ground truth (ld never
  cross-resolves them); any disagreement on the back-computed section
  base fails the base build with per-symbol evidence.
- **`-Map` oracle** (`GRAFT_MAP_ORACLE=1`, on in the e2e suite and the
  hardware loop): base asks ld for its map and verifies every
  recovered per-node address against it; mismatch fails the base
  build. First run caught the TLS bug (st_value is a TLS-template
  offset, not a vaddr) — TLS sections are now excluded from the table
  and a positional ref to one bails.
- **e2e shape coverage** (x86, no hardware): mutable-static aliasing
  (scenario F), section-cycle resolution (G), entry-cut /
  caller-not-re-emitted (`entry_cut_keeps_caller_in_base`), plus the
  unit-level pins in `nominal_identity.rs` (salt, SCC distinctness).

## Status (2026-06-10, rev 5 — hardware-validated)

Implemented and validated end to end: x86 `e2e_cycle` (full cycle + all
five payload edits), `prune_channels` (19 tests incl. the
ambiguous-mutable bails), `nominal_identity` (salt behavior), and **the
esp32s3 hardware loop**: probe-instrumented base boots; the Hello→Howdy
overlay builds (closure 16, 15 abs-rewrites, 0 ch3), flashes, and runs
correctly — statics count independently, `ram_resident_step` resolves to
base IRAM at the right address, `main` is *not* re-emitted (trampoline
cut holds). Schema is v4 (the hash domain changed twice; v3 bases fail
loud).

The 15 strong-UND symbols observed in overlay.elf (`Reset`,
`__default_*`, `__atoi`…) were a red herring: linker-script
`EXTERN()`/`ENTRY()` residue, referenced by no reloc, harmless at 0.

## Open / TBD

- **Address recovery coverage.** Majority-vote back-compute handles the
  common weak-outlier case; all-weak / symbol-less sections need `-Map`
  or an injected anchor. Keep trying methods until base can pin *every*
  retained section it might be asked about, then the "absent → bail"
  path becomes unreachable rather than load-bearing.
- **Same-named local statics across TUs** (C-style `static int counter;`
  in several files): salted hashes collide only if content also matches;
  then both bail paths above fire loudly. If this bites real esp-idf
  builds, extend the salt with `tu_id` for locals — at the cost of
  exposure to STT_FILE instability for rcgu objects.
- **Function-pointer identity under exec representative resolution.** An
  ambiguous read-only/exec hash resolves named refs via symtab pin but
  `STT_SECTION` refs to the representative copy; two identical functions
  compared by address could observe the "wrong" copy. ICF-class risk,
  accepted for now.

## Sequencing

1. x86 repro in `tests/prune_channels.rs`: a weak symbol in two
   multi-symbol sections with differing neighbors; positional resolution
   must land in a valid copy where the old symhash path bailed.
2. `metadata` → `SectionEntry`; `base` → per-node address recovery
   (majority-vote); `overlay` → section table + offset map, classify via
   `trans_hash`; `prune` → positional resolution, delete the surrogate.
3. Delete the `symhash` layer once nothing references it.
4. Green x86 `e2e_cycle` + `prune_channels`; then hardware Hello→Howdy.

## Alternatives considered (and rejected)

- **Per-symbol nodes (rev 1).** Unsound — relocless intra-section jumps.
- **Per-symbol symhash table with all-weak-views recorded (rev 2).**
  Works, but keeps the name central and the surrogate; the section table
  subsumes it with less code.
- **Synthetic `.o` with a weak-reloc list so ld fills the table.** Clever
  but (a) you still need a symbol ld resolves to each section's start
  (section symbols are object-local, not referenceable across objects —
  same anchor requirement as injection), and (b) any live reference pins
  its target, so a metadata section referencing everything defeats base's
  `--gc-sections` and bloats the image; a discardable one is GC'd before
  it can carry the addresses out. Fights gc, adds no power.
- **Pure content identity (drop names entirely).** Loses the collision
  tiebreaker. Keep the name for that narrow case only.
