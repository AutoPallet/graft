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
