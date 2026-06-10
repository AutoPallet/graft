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

## prune's resolution channels are ordered for a reason

`prune_object`'s reloc resolution is a cascade. The ordering is load-
bearing, not cosmetic:

1. overlay saw it AND it's in the closure → UND (ld resolves to
   overlay's re-emitted copy).
2. overlay saw it AND its symhash matches base → SHN_ABS anchor at
   base's address (content-identical, safe).
3. **overlay saw it but neither of the above** → BAIL. The symbol's
   content differs from base and it wasn't re-emitted; binding to
   base's address would silently call base's stale code. This check
   MUST come before channel "base_symtab" (M2 fixed a bug where it
   came after and was shadowed — channel 3 silently bound drifted
   content to base).
4. overlay never saw it (`overlay_sh.is_none()`) AND base_symtab has a
   unique address → SHN_ABS anchor + post-link verify. This is the
   channel-of-last-resort, ONLY for names not in overlay's inputs
   (crt/startup, linker-script absolutes, ROM/PROVIDE, prebuilt libs).
   Ambiguous base names (multiple distinct addresses) bail.

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
