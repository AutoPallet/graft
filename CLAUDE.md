# Notes for Claude

Project-specific lessons from past mistakes. Read before adding code that
"just makes an error go away."

## Don't paper over symbol-resolution failures with fallbacks

When prune (or anything else in the symhash pipeline) bails because it
can't resolve a symbol, the impulse is to add a "lazy-archive miss"
fallback that name-looks-up the symbol against `base.elf`'s `.symtab`
and uses whatever address is there. **Don't.**

Two reasons:

1. **It's unsound.** The whole point of routing every base-bound
   reloc through the symhash table is so that if the symbol's content
   (or anything it transitively depends on) has changed between base
   and overlay, the closure walk pulls it into the overlay and we
   emit it UND for ld to resolve to overlay's re-emitted copy. A
   bare name→address lookup against `base.elf` skips that check
   entirely: an overlay built against modified libunwind (or some
   symbol that libunwind transitively depends on) would silently
   bind to base's stale address, and at runtime the overlay would
   call into base's old code. The bug would be invisible at link
   time and possibly invisible at runtime until something with
   different bytes got dispatched.

2. **It hides real bugs.** The reason a symbol isn't in
   `overlay_symhash_globals` is almost always that some upstream
   discovery step is missing it — an archive demand-load filter
   that's wrong, a scan-input list that doesn't match the linker's,
   etc. Adding a fallback at the resolution site means you never
   find the upstream bug, and the next person who hits a related
   issue has to debug *through* the fallback. (M1.u: the "missing"
   `_Unwind_Resume` was a one-line bug in `classify_bind` that mapped
   UND symbols to `SymbolBind::Local`, causing demand-load to skip
   every UND-resolves-to-archive case. The fix was four lines in
   `elf.rs`. The fallback would have been ~40 lines plus an unsound
   resolution path.)

If a build fails because of an unresolved symbol, the answer is:

- **First**, ask "why does ld see this symbol when graft doesn't?"
  ld is the reference implementation; if our scan/closure walk
  diverges from it, that divergence is the bug.
- Check `classify_bind` and the demand-load loop in `scan.rs` —
  they're the most common source of "graft sees less than ld."
- Check `resolve_scan_inputs` in `overlay.rs` — eager vs deferred
  partitioning, `-l<name>` resolution.
- Only after confirming the discovery pipeline is correct should
  you consider adding explicit handling for the symbol. And even
  then, prefer narrow, named channels (e.g. `script_absolute_names`
  for SHN_ABS-in-base symbols defined by linker scripts) over
  generic name→address fallbacks.

## "Tests pass" can mean "tests didn't run"

The e2e test fixture's `cargo clean -p app` was silently a no-op
because the fixture pins target=musl and the `--target` flag wasn't
passed. Cargo treated the stale binary as Fresh, the test ran an
old build, the assertions passed against old behavior. M1.s exposed
this: fixing the clean uncovered a latent overlay-mode bug (the
GOTPCREL miscompile, M1.t) that had been masked for who knows how
long.

When a test depends on a `cargo build` invocation actually re-running
the linker, verify that. `cargo build -vv` shows whether cargo decided
to relink or skipped as Fresh.

## Don't trust file mtimes for "did it rebuild"

`/tmp/graft-e2e-base.elf` had an mtime from the *previous* test run
even after the current run "completed" the copy step — because the
copy was a no-op when source and dest had identical content. The
binary's correctness can't be inferred from its existence or
freshness; verify by content-hash or by running it.

## Reloc rewrites: GOT-flavored relocs aren't transparent in addend

The single-`__graft_const + (vaddr+A)` SHN_ABS trick from v1 of the
anon-provide design works for direct-write relocs (PC32, ABS32,
ABS64) where the linker writes `S + A` straight into the slot. It
**doesn't** work for `R_X86_64_GOTPCREL` and friends: the linker
populates the GOT slot with the symbol *value* `S` (= 0), not
`S + A`. The addend miscombines into the instruction's disp.

The fix is per-target SHN_ABS symbols (`__graft_sym_<symhash>`,
st_value = vaddr) where the GOT slot ends up holding `vaddr`
directly. See `docs/11-anon-provide.md` and M1.t.

If you're tempted to special-case a reloc type by patching
instruction bytes (mov→lea, etc.), step back and check whether
content-keyed per-target symbols would handle it uniformly without
any byte patching. They usually do.

## The resolution channels are ordered for a reason

Reloc resolution is a cascade, and it lives in ONE place:
`resolve::Resolver::dispose` (prune is a dumb rewriter that only wires
intra-object internal targets and emits what dispose tells it). The
scan records every reloc's resolution once (`graph.reloc_targets`);
hashing edges, the closure walk, and disposition all consume that same
answer — never re-resolve a name elsewhere, that's how "classify vs
resolve disagree" bugs happen. The ordering is load-bearing, not
cosmetic:

1. overlay saw it AND its node's trans_hash is in the closure → UND
   (ld resolves to overlay's re-emitted copy). STT_TLS when the target
   node is SHF_TLS — ld rejects TLS-def-vs-non-TLS-ref binds.
2. overlay saw it AND its trans_hash is in base's section table →
   anchor at `by_section[th] + offset` (positional, content-keyed, no
   verify). Ambiguous hashes (base placed identical content at several
   addresses): unique name in base.symtab → pin that copy + verify; no
   pin and the content is MUTABLE → bail (aliasing distinct
   variables); read-only/exec → representative.
3. **overlay saw it but neither of the above** → BAIL. The symbol's
   content differs from base and it wasn't re-emitted; binding to
   base's address would silently call base's stale code. This check
   MUST come before channel "base_symtab" (M2 fixed a bug where it
   came after and was shadowed — channel 3 silently bound drifted
   content to base).
4. overlay never saw it AND base_symtab has a unique address →
   anchor + post-link verify. This is the channel-of-last-resort, ONLY
   for names not in overlay's inputs (crt/startup, linker-script
   absolutes, ROM/PROVIDE, prebuilt libs). Ambiguous base names
   (multiple distinct addresses) bail.

Anchor encoding (docs/15, `basemap.rs`): prune emits anchors as UND
`__graft_assumed_<vaddr>` references; ONE synthetic base-map object
defines them — as section symbols inside NOBITS map sections placed at
base's layout (positional content; PIE-compatible), in SHF_TLS map
sections reproducing base's PT_TLS geometry (ld computes all TP
offsets — graft owns zero tpoff arithmetic), or SHN_ABS *only* for
vaddrs outside every PT_LOAD (true constants: esp32 ROM). Map sections
carry `__graft_map_keep_*` GC-root symbols passed via `--undefined=` —
the TLS maps define PT_TLS geometry (memsz/align, which TP offsets are
end-anchored against) and must survive `--gc-sections` even with zero
live references into them. Re-emitted/new thread-locals land in
`GRAFT_TLS_SLACK`, an in-template hole reserved at base link (the
template can NEVER grow at combine time); post-link, overlay PT_TLS
geometry must equal base's exactly — `verify_tls_geometry` bails
otherwise.

The invariant: a name overlay's scan saw with differing content never
reaches base_symtab resolution. If you reorder these, you can
reintroduce a silent stale-bind. `tests/prune_channels.rs` pins every
channel including the two bail paths — keep it green.

## scan must mirror ld, including what it DOESN'T pull

`scan`'s archive demand-load is graft's model of ld's lazy resolution.
ld extracts an archive member only for a *strong* (STB_GLOBAL)
undefined reference — never for a weak undef (those resolve to 0).
graft must match: demand-load triggers on `Global` only. Over-pulling
on weak undefs makes graft include+call code ld would have left null,
so base (real ld) and overlay disagree on whether a weak symbol is a
function or zero — an invisible runtime divergence. Same principle as
"don't paper over symbol-resolution failures": when graft's view of
the inputs diverges from ld's, that divergence is the bug.

## One overlay layout mode: splice

There is no "append" mode anymore. Overlay sections are always linked
into base's reserved slack (`GRAFT_*_SLACK`) and byte-spliced in place;
RAM-resident segments that legitimately fall past base (xtensa
`.rwtext`) are appended by `combine::append_pt_loads`. If you find
yourself reaching for a fresh-PT_LOAD "append everything" path, that's
the retired design (it never worked on xtensa — one IROM/DROM segment
only — and carried the trickiest ELF surgery in the tree). Reserve
more slack instead.

Slack only works if the target's linker script *scoops* the slack
input sections via wildcards (`*(.text.*)` etc.). A script with no
matching rule makes ld orphan-place the section — it lands wherever ld
guesses and can silently change segment layout: esp-hal's linkall.x
has no `*(.tdata*)` rule, so the TLS slack joined the IROM LOAD,
flipped it writable, and the ESP ROM bootloader crash-looped (no
link-time symptom; found on hardware). `check_slack_scooped` in
base.rs now fails the build on any orphaned `*.graft_slack` output
section; bare-metal targets without a TLS runtime opt out via
`GRAFT_TLS_SLACK_LEN=0` (the esp32s3-hello fixture does).

## Content identity is only sound for immutable content

Two byte-identical sections are interchangeable ONLY if they're
read-only or code. `.bss` sections have no bytes at all; zero-init
`.data` sections are all byte-identical — but they are *distinct
mutable variables*, and binding a reference to "an interchangeable
copy" silently aliases program state (M2 xtensa: `TICK_COUNTER`,
`ATOMIC_TICK`, and esp_println's `TIMED_OUT` all bound to one address;
`esp_println::LOCK` aliased `ESP_HAL_LOCK`). ld itself never
content-folds writable sections — mirror it.

`SectionInfo::content_addressable` is the predicate (has bytes AND
(read-only OR exec)). Non-addressable sections get a nominal salt
(sorted symbol/offset pairs, `.llvm.<id>` stripped) folded into their
hash, and prune refuses representative resolution for ambiguous
mutable hashes. If you're adding a resolution path, ask: "could this
bind two distinct mutable variables to one address?" If yes, it needs
a name pin or a bail. `tests/nominal_identity.rs` pins the predicate.

## trans_hash is per-node; SCC members must NOT share one

Code and its literal pool reference each other on xtensa
(`.rwtext` ↔ `.rwtext.literal`), so they ALWAYS form an SCC. If SCC
members share a hash, `by_section[th]` is ill-defined: base records
one hash at two addresses, the ambiguity machinery treats them as
"identical copies", and resolution lands in the wrong section (M2:
`ram_resident_step` resolved into the middle of the literal pool —
runtime jump to garbage). The per-node hash is
`blake3(scc_hash ‖ member_input_hash)` (see `hash::compute`). Never
"simplify" it back to the bare SCC hash; equality of trans_hash must
mean "interchangeable bytes at a recoverable address."

## The container bind-mounts the repo root — git affects the host

`docker exec graft-esp32s3 … /workspace` IS the host checkout. A
`git stash`/`checkout`/`clean` run inside the container (or in any
scripted container command) hits the real working tree — with the
refactor uncommitted, a stray `git stash` wiped every in-flight
change mid-session (recovered via `git stash pop`). Never put git
state commands in container scripts; run them deliberately on the
host only.

## Section names are not unique within an object

The esp32s3 rcgu carries TWO `.rwtext` input sections; ELF allows any
number of same-named sections per object. Any name-keyed lookup of a
section ((obj, name) → index/hash/node) silently picks an arbitrary
one — the resolve-once refactor's first cut did this and anchored
`ram_resident_step`'s literal into the wrong `.rwtext` (caught by the
hardware loop, now also impossible per `CanonicalReloc::target_section`).
Section identity within an object is the PHYSICAL INDEX; names are for
diagnostics. The index is cleared before hashing (indexes shift under
CGU repartition) — the canonicalized content fingerprint is the
hash-stable identity.
