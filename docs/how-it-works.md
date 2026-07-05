# How graft works

graft is a linker shim. rustc invokes it in the linker seat; it either
forwards argv to the real linker unchanged (passthrough) or does one of
three jobs: a **base** link, an **overlay** link, or a **combine**. A
fourth mode, **auto**, picks base vs overlay per output and falls back to
base on any overlay failure.

The output of every mode is an ordinary ET_EXEC ELF that boots the normal
way. There is no runtime, no hot-patch loader, no jump table baked into
the program. All the cleverness is at link time.

This doc is the maintained account of what each mode does and why it is
sound. For the identity model it rests on, read
[`14-identity-granularity.md`](./14-identity-granularity.md); for the
xtensa relaxation walk it uses to locate bytes in a relaxed base, read
[`16-relaxation-walk.md`](./16-relaxation-walk.md).

## The identity atom: `trans_hash`

Everything downstream keys on one value. graft models the link as a graph
of **nodes** — one per input section (the linker's ship/diff atom). Each
node gets a `trans_hash`: a transitive content fingerprint over the
section's own bytes, its canonicalized relocations, and its entire
successor subgraph. Two nodes with equal `trans_hash` are byte-identical
*and* everything they transitively reference is byte-identical, so they
are interchangeable at a recoverable address.

The hash is computed by per-SCC color refinement (`hash.rs`): sections
that reference each other cyclically (xtensa code and its literal pool
always do) form a strongly-connected component; colors are refined within
the SCC to a fixed point, `scc_hash = blake3(sorted member colors)`, and
each node's `trans_hash = blake3(scc_hash ‖ color(node))`. The per-node
mix matters — SCC members must not share a hash, or `by_section[hash]`
becomes ambiguous and resolution can land in the middle of the wrong
section (see `14` and CLAUDE.md).

Content identity is sound only for immutable content. A node is
`content_addressable` only if it has bytes AND is read-only or
executable. `.bss` (no bytes) and zero-init `.data` (all byte-identical
but distinct mutable variables) get a nominal salt folded into their hash
and are never resolved by a shared representative — binding two distinct
variables to one address is the exact bug the salt prevents.

---

## Base link (`GRAFT=base`)

`base.rs`. The base link is passthrough-plus: the real linker does the
real link, and graft rides alongside to record where everything landed.

1. **Pre-scan under the linker.** graft spawns the scan (`scan.rs`:
   hash + build the node graph, compute every node's `trans_hash`) on a
   background thread while the real linker runs on the same read-only
   inputs. The hashing hides under ld's runtime. The scan mirrors ld's
   own demand-load semantics exactly — an archive member is pulled only
   for a *strong* (STB_GLOBAL) undefined reference, never a weak one — so
   graft's view of the inputs matches ld's. Divergence from ld is a bug.

2. **Slack balloons.** Splice is the only overlay layout mode, so base
   must reserve empty space for a future overlay to land in.
   `slack.rs` synthesizes one `.o` carrying a `.text` and a `.rodata`
   slack (`0xFF`-filled, so a fresh-erased NOR sector and an unwritten
   slack sector are bit-identical) plus a zero-filled `.data` and TLS
   slack (re-emitted `.bss` / zero-init thread-locals must read zero),
   each with a `GRAFT_*_SLACK` cover symbol, injected into argv as an
   ordinary
   input and kept alive with `-Wl,--undefined=GRAFT_*_SLACK`. The
   target's linker script must **scoop** these via its existing
   wildcards (`*(.text.*)`, `*(.rodata.*)`, …) so they land inside base's
   normal output sections, same layout as if the user had declared the
   statics themselves. If a script has no matching rule ld orphan-places
   the slack — it lands wherever ld guesses and can silently flip segment
   layout (this crash-looped the ESP ROM bootloader once, no link-time
   symptom). `check_slack_scooped` re-opens the output and fails the
   build loudly on any orphaned `*.graft_slack` output section. Sizes are
   env-driven (`GRAFT_TEXT_SLACK_LEN`, …); slack is reserved once here and
   can never grow at combine time. Bare-metal targets with no TLS runtime
   set `GRAFT_TLS_SLACK_LEN=0` to opt the TLS balloon out.

3. **Address oracle.** graft always adds `-Wl,-Map=<output>.graft-map`.
   The linker map is the authoritative source of each input section's
   *placed* address and *post-relaxation* size — neither of which can be
   recovered from symbols once ld rewrites section interiors on a
   relaxing target (`mapcheck.rs`).

4. **Optional ICF fold.** With `GRAFT_ICF=1` (default off) graft folds
   `trans_hash`-identical Rust code sections before the real link, by
   symmetric weak aliasing, so ld's `--gc-sections` collects the
   duplicates. GNU ld has no ICF and rustc emits cross-crate
   monomorphization copies nothing else folds. This trades the
   scan-under-the-linker overlap for a serial scan→rewrite→ld pipeline.
   The mechanism, its safety criteria (Rust rcgu exec sections only, no
   mutable/rodata folding, group chunking), and the post-fold byte
   verifier are all in `icf.rs`.

5. **Manifest attach.** After the link lands, graft re-opens the output
   for `.symtab` addresses, joins them with the pre-scan's hashes, and
   attaches two non-alloc (`SHF_ALLOC=0`) sections to the ELF:
   `.graft.manifest` (root record — schema version, hash-algo version,
   entry symbol, toolchain stamp, build-id) and `.graft.sections` (the
   content-keyed table: `trans_hash → placed address + size`). These are
   postcard-encoded and schema-versioned; a stale base fails loud rather
   than mis-resolving (`metadata.rs`, `SCHEMA_VERSION`).

The output is a normal executable plus two inert metadata sections. A
base link is strictly heavier than a plain link (scan + map + attach),
which is why `auto` only pays for it on the first link or a fallback.

---

## Overlay link (`GRAFT=overlay`, needs `GRAFT_BASE_ELF`)

`overlay.rs`. The overlay link re-links only what an edit changed and
resolves everything else positionally against the base. This is where the
soundness argument lives.

1. **Scan again.** Same `scan.rs` pass as base, over the current inputs,
   with the entry symbol read back from base's manifest so both agree on
   where the graph is cut.

2. **Closure of changed content.** Starting from the entry root, graft
   walks the node graph and includes a node iff its `trans_hash` is *not*
   present in base's section table — i.e. its content (or something it
   transitively references) changed. Unchanged subgraphs are marked
   Provided and not walked into: base already satisfies everything
   reachable from them. The result is the transitive closure of changed
   sections — usually a handful out of hundreds of thousands
   (`compute_closure`).

3. **Resolve every reloc — the cascade.** For each relocation in a kept
   section, `resolve.rs`'s `Resolver::dispose` decides what the pruned
   object should emit. The scan resolved each reloc's target *once*
   (`graph.reloc_targets`); the closure walk and disposition consume that
   same answer, so inclusion and resolution can't disagree. The order is
   load-bearing (CLAUDE.md, "The resolution channels are ordered for a
   reason"):

   1. **Target is in the closure → UND.** Overlay re-emits the target;
      ld binds the reference to overlay's fresh copy. (STT_TLS when the
      target is SHF_TLS — ld rejects TLS-def-vs-non-TLS-ref binds.)
   2. **Target's `trans_hash` is in base's table → anchor** at
      `by_section[hash] + offset` (positional, content-keyed, no verify).
      If the hash is ambiguous (base placed identical content at several
      addresses): a name unique in base's symtab pins that copy and
      verifies; no pin and the content is **mutable → bail** (would alias
      distinct variables); read-only/exec → a representative copy is fine.
   3. **Overlay saw the target but neither of the above → BAIL.** Its
      content differs from base and it wasn't re-emitted; binding to
      base's address would silently call base's stale code. This check
      **must** come before channel 4, or a drifted definition gets
      shadow-bound to base (the M2 bug).
   4. **Overlay never saw the target and base's symtab has a unique
      address → anchor + post-link verify.** Channel of last resort, only
      for names not in overlay's inputs (crt/startup, linker-script
      absolutes, PROVIDE/ROM constants, prebuilt libs). An ambiguous base
      name (several distinct addresses) bails; a weak undef mirrors to a
      weak UND (base resolved it to 0 too).

   The invariant: a name overlay's scan saw with differing content never
   reaches channel 4. That is the whole stale-bind guarantee.

4. **Walk-refusal fixpoint (relaxing targets).** On xtensa, ld rewrites
   section interiors, so a channel-2 positional anchor `value + addend`
   into a relaxed base section needs offset translation — graft replays
   ld's exact edit set (`relax/`, see `16`) to locate the byte. Where the
   walk **refuses** (ambiguous fate, deleted bytes, unwalkable node),
   there is exactly one sound recovery, and it depends on mutability:
   re-emit the target if it is content-addressable — base keeps calling
   its own copy, the overlay just carries a fresh one — but **hard-bail**
   if it is mutable, because re-emitting a variable would fork it into two
   live copies. Re-emitting adds sections (and their relocs) to the
   frontier, so `compute_closure_fixpoint` iterates until no node is
   pulled; by construction dispose then never sees a refusal. The walk
   runs only for offsets an actual reloc queries — off-frontier ambiguity
   costs nothing.

5. **Prune.** `prune.rs` rewrites each kept `.o` down to its live
   sections and rewrites relocations per the dispositions: internal
   targets are wired to sibling kept sections; every base-bound reloc
   becomes an UND reference to `__graft_assumed_<vaddr>` (the reloc's own
   addend rides along, except walk-translated anchors that fold
   `value + addend` into one output offset). Prune is a dumb rewriter —
   it never resolves a name itself.

6. **Base-map object.** `basemap.rs` synthesizes **one** ET_REL object
   that *defines* every `__graft_assumed_<vaddr>` the pruned objects
   reference. The encoding rule (from `15`, implemented):

   - vaddr inside a base PT_LOAD → an ordinary symbol inside a **NOBITS
     map section** placed (via layout script / `--section-start`) at the
     base address span it mirrors. A section-defined symbol keeps the
     resolution *image-relative* (PIE-safe), where SHN_ABS would lose a
     load bias. Map sections mirror base's layout minus the slack
     carve-outs and minus the PT_TLS span.
   - vaddr inside base's PT_TLS template → a symbol in an **SHF_TLS map
     section** that reproduces base's PT_TLS geometry (memsz/align). ld
     rebuilds an identical-geometry PT_TLS and recomputes every TP offset
     itself — graft owns zero tpoff arithmetic.
   - vaddr **outside every PT_LOAD → SHN_ABS**. Only true constants
     (esp32 ROM/PROVIDE addresses) take this path.

   Map sections carry `__graft_map_keep_*` GC-root symbols passed via
   `--undefined=`, so `--gc-sections` can't drop a TLS map whose geometry
   still matters even when no live reloc points into it.

7. **Real link into the slack.** graft shells out to `$GRAFT_REAL_LD`
   with the pruned `.o`s + the base-map object and a layout that places
   overlay `.text`/`.rodata`/`.data` at the base-reserved slack vaddrs
   (x86: a SECTIONS block; xtensa: esp-hal's own scripts with only
   `memory.x` ORIGIN/len nudged past base's used flash). Overlay is a
   **full** static link: every symbol resolves either to a closure-local
   definition or to a base-map anchor. This requires base to be a non-PIE
   ET_EXEC so every base byte has a permanent absolute address to pin.

8. **Post-link verify.** graft re-opens the overlay ELF and checks every
   channel-4 `assumed_names` entry actually landed at the address graft
   assumed (`verify_assumed_names`), and — when base has a real PT_TLS —
   that overlay's PT_TLS geometry equals base's exactly
   (`verify_tls_geometry`). A mismatch bails; these are the last line
   against a silent shift.

The output is `overlay.elf`: a fully-linked image whose live bytes sit in
the slack vaddrs, references into base already resolved to constants.

---

## Combine (`graft combine base.elf overlay.elf -o out.elf`)

`combine.rs`. Pure splice — no relocation work, because the overlay link
already resolved every base reference to an absolute address.

1. Copy base.elf verbatim.
2. Byte-splice each overlay section over the `0xFF` slack bytes at its
   file offset inside base's existing segments. RAM-resident segments
   that legitimately fall past base (xtensa `.rwtext` copied flash→IRAM
   at boot) are appended as fresh PT_LOADs by `append_pt_loads`;
   everything else splices in place, so the image keeps base's exact
   shape and size.
3. Install **one** trampoline at base's `entry_symbol` (default `main`),
   redirecting crt (or the boot path) to overlay's entry. Always the
   long-jump form — graft never emits a narrow/short variant (`arch.rs`).
   This is the only trampoline needed: any base section that pointed into
   the closure would have had its own `trans_hash` cascade and been
   pulled into the closure, so closure members are only reached from
   within the closure. The sole exception is `_start → main`, because
   crt1.o isn't an overlay scan input.
4. Recompute the build-id as `blake3(base_id ‖ overlay_id)[..len]` — the
   overlay link produced its own build-id from the pruned inputs;
   composing the two published identities is deterministic and stable
   (`refresh_build_id`).

Because only the slack bytes and one trampoline differ from base, a
sector-diff flasher writes only the handful of 4KB sectors that changed.

---

## Auto mode (`GRAFT=auto`)

`auto.rs`. Self-managing: only the linker invocation can see whether a
base snapshot exists for *this* output, whether its manifest still
matches, and whether the overlay fits the slack.

- **No snapshot** (or `GRAFT_REBASE=1`) → full base link, then copy the
  attached output to `<output dir>/.graft-auto/<output>.base.elf`.
- **Snapshot exists** → overlay against it; on success the snapshot is
  untouched (every overlay links against the same base).
- **Overlay fails for any reason** → one loud line with the reason, then
  a full base relink and a fresh snapshot.

The snapshot path is deliberately *not* stem-prefixed, so `cargo clean -p
<crate>` costs an overlay, not a base relink, while a full `cargo clean`
wipes it. The fallback turns every overlay bail into "the build still
succeeds, just slower" — always correct, sometimes slower.

---

## Failure philosophy

Every ambiguity is a loud refusal at link time, never a runtime guess. A
guess here is a *silent* miscompile — base and overlay disagreeing about
an address, a variable aliased, stale code dispatched — so graft would
rather fail the link. The doctrine (CLAUDE.md, "Don't paper over
symbol-resolution failures"): when graft's view diverges from ld's, that
divergence is the bug, not something to fall back around. Under `auto`
every one of these refusals is caught and converted to a full base
relink, so the build never breaks. The main refusal classes:

- **Unresolvable symbol** — a name overlay saw with differing content
  that reached neither the closure nor base's table (channel 3). Never
  papered over with a name→address lookup against base.
- **Ambiguous mutable hash** — identical mutable content at several base
  addresses with no unique name to pin (channel 2a).
- **Weak/weak divergence** — a weak symbol with multiple differing weak
  definitions and no strong override; ld's bind is link-order-dependent
  and graft can't track it soundly. Base warns (plain ld semantics),
  overlay refuses.
- **Walk refusal on mutable content** — a relaxed-base positional anchor
  the walk can't translate, where re-emitting would fork a variable.
- **TLS geometry drift** — overlay's PT_TLS memsz/align doesn't match
  base's; every TP offset would shift.
- **Slack overflow** — the overlay payload doesn't fit the reserved
  balloon (slack can't grow at combine time).
- **Stale / incompatible snapshot** — manifest schema or hash-algo
  version mismatch, or an argv reshape; the base is not a valid oracle
  for this overlay.
