# 03 — The build pipeline (CLI side)

Where patches actually come from. All references into
`packages/cli/src/`.

## BuildMode

`build/request.rs`, the `BuildMode` enum:

| Variant | Purpose |
|---|---|
| `Base` | Plain `cargo build`, no subsecond mangling. |
| `Fat` | Initial "golden" build. Everything exported, nothing GC'd. |
| `Thin { aslr_reference, workspace_rustc_args, modified_crates, changed_files, cache }` | A patch build. |

The `Fat` ↔ `Thin` pair is the whole pipeline. A session runs exactly one
Fat build on startup and one Thin build per file-change event.

## Fat build: capturing the reference image

The fat build is a normal `cargo rustc` invocation but with three critical
tweaks (`build/request.rs:768-1851`, the relevant args are added around
`:775` and `:1775-1851`):

1. `-C linker=dx` with `NoLink` mode set via env vars. This means *rustc
   thinks it's linking* but `dx` just dumps the linker args to a file and
   writes a dummy object. `dx` itself does the real link from the parent
   process, giving it full control.
2. `-C link-arg=-Wl,--export-dynamic` (Linux) / `-Wl,-all_load` (macOS) so
   every symbol ends up in the dynamic symbol table and is reachable via
   `dlsym`.
3. `-C link-arg=-Wl,--no-gc-sections` so the linker doesn't drop functions
   that only get called through the patch later.

Plus `RUSTC_WRAPPER=dx` so every rustc command gets logged to
`target/dx-rustc/{crate_name}.{bin,lib}.json` (`rustcwrapper.rs:96-136`).
These JSON files store the exact argv and full environment, which is what
makes replay possible.

For WASM, the fat build's output is additionally post-processed by
`prepare_wasm_base_module()` (`build/patch.rs:~1316`), which promotes every
function into the indirect-function table so that patches can later call
them without needing a direct export.

## Change detection

`serve/runner.rs:1281-1326` + `serve/mod.rs:85-90` + `build/builder.rs:364-454`.

1. `notify` crate watches the workspace. On change, emits
   `ServeUpdate::FilesChanged { files }`.
2. `order_changed_crates(files)` → `file_to_workspace_crate(path)` for each
   file. Walks `Cargo.toml`s and picks the *longest* matching crate root;
   sorts by dependency depth (deepest first).
3. `patch_rebuild()` BFSes dependents via `workspace_dependents_of()` to
   compute the transitive closure. Adds that set to the session's
   `modified_crates` — which is **cumulative**, never reset until the next
   fat build.

So if you edit `util.rs` in a leaf crate, every workspace crate that depends
on it (including the tip bin) is marked modified; all of those get replayed
in the next thin build.

Why cumulative? Because Rust monomorphization means a change to a generic
function in a dep surfaces as changed code in *every* caller's codegen
units. Replaying all of them guarantees no stale object files.

## Thin build: the replay

`build/link.rs:132-335`, the function `compile_workspace_hotpatch`:

1. **Topologically sort** the modified crates
   (`workspace_hotpatch_replay_order`, `link.rs:612-660` — Kahn's).
2. **Replay rustc** for each, using the JSON blob captured during the fat
   build. This produces updated `.rlib`s in the target dir, overwriting
   the fat build's. Importantly rustc's own incremental cache (`.rcgu.o`
   files per codegen unit) only re-emits objects whose AST changed — this
   is the source of the "incremental" in "incremental compilation", and
   it's `rustc`'s feature, not Dioxus's. Dioxus just orchestrates.
3. **Collect tip-crate `.rcgu.o`s** from the new codegen. These are the raw
   object files that would have gone into the final executable.
4. **Gather workspace rlibs** (preserving fat build link order) plus the
   fresh tip crate objects.
5. **Build an undefined-symbol stub object.** This is the key innovation —
   see next section.
6. **Invoke the real linker** with thin-link args: `-shared` on Linux,
   `-Wl,-dylib` on Mach-O, `-pie --allow-undefined --import-memory` for
   wasm. The output is `libpatch-{timestamp}.so`.
7. Clean up stale objects so `dlopen` doesn't hit a cached copy.

`thin_link_args` (`link.rs:341+`) strips out everything that isn't workspace
rlibs or essential system flags — no libstd, no libc, no frameworks — so
the patch stays tiny and fast to link.

## The undefined-symbol stub — the trick that makes it work

This is the most interesting piece. `build/patch.rs:852-1260`,
`create_undefined_symbol_stub`.

After replaying rustc, the tip-crate codegen units reference a pile of
symbols that are **not in any of the linked rlibs** — references into
dependencies we deliberately excluded from the thin link (because their code
is already in the original binary at known addresses).

If we tried to link right now, the linker would error on undefined symbols.
So instead we *synthesize an object file that defines them all*:

- For each undefined `Text` symbol, we look up its absolute address in the
  cached symbol table of the original fat binary, then emit a tiny native
  trampoline that hard-codes that address and jumps to it. Examples from
  `patch.rs:1083-1120` (Unix):

  ```
  x86_64:   FF 25 00 00 00 00    ; jmp qword [rip+0]
            <8 bytes: abs addr>  ; (absolute 64-bit target)

  aarch64:  58 00 00 50          ; LDR X16, [PC, #0]
            D6 1F 02 00          ; BR X16
            <8 bytes: abs addr>

  arm32:    E5 1F F0 04          ; LDR PC, [PC, #-4]
            <4 bytes: abs addr>

  x86_32:   E9 <rel32>           ; jmp rel32 (abs_addr - 5)
  ```

  Windows variants (`:1015-1082`) use the same pattern but with
  platform-appropriate calling conventions (MOVZ/MOVK quad on ARM64,
  movabs+jmp on x64, etc.).

- For undefined `Data` symbols we emit a symbol with `value = abs_addr` and
  `section = SymbolSection::Absolute` — the linker happily binds callers
  to that literal address.

- For `Tls` symbols we synthesize per-patch TLS initializers from the
  `.tdata` / `__thread_data` section of the original (`:1163-1227`), with
  correctly-computed sizes (on Mach-O, sizes come from the
  `FOO$tlv$init` symbol adjacency table we built during caching).

The resulting stub object is just another input to the final link, exactly
like a user's `.o`. Now the linker sees every reference resolved and
produces the patch `.so` / `.dylib` — a valid shared object that, when
loaded, will jump into the running binary for every call site we didn't
redefine.

**That's the whole scheme.** The patch is a `.so` whose "undefined" symbols
have been satisfied by trampolines to hardcoded absolute addresses. Combine
that with rebasing by the `main`-anchored ASLR delta and every unchanged
call goes to the original code; every changed call hits a freshly compiled
version.

## The HotpatchModuleCache

`build/patch.rs:67-346`. On the first patch after a fat build, we parse the
original binary's symbol table (ELF/Mach-O via `object`, PDB via `pdb`,
wasm via `walrus`/`wasmparser`) and cache it. Re-parsing a large binary
every patch is expensive: the doc comment cites the Dioxus website going
from a 3s patch to a 1.1s patch just from caching.

The cache holds:

- `symbol_table: HashMap<String, CachedSymbol>` — name → (addr, kind, size,
  flags, weakness, defined?)
- `tls_init_data: Vec<u8>` — raw bytes of `.tdata` / `__thread_data`
- `tls_init_sizes: HashMap<String, (offset, size)>` — per-TLS-symbol init
  range
- `old_wasm`, `symbol_ifunc_map`, `old_exports`, `old_imports` — wasm-only

## JumpTable assembly

`build/patch.rs:394-443` for ELF/Mach-O, `:349-392` for Windows PDB,
`:458-761` for wasm.

Native path is trivial once the cache and the patch exist:

```rust
for (new_name, new_addr) in patch_symbols {
    if let Some(CachedSymbol { address: old_addr, .. })
        = cache.symbol_table.get(new_name)
    {
        map.insert(old_addr, new_addr);
    }
}
```

i.e. *for every symbol that exists in both*, record the mapping. That's the
whole jump table. Plus we separately record `new_base_address` (address of
`main` in the patch) and `aslr_reference` (address of `main` in the fat
binary); the runtime uses both to do the rebase.

## Why thin linking is fast

The "500ms incremental build" claim in the subsecond README decomposes as:

- rustc already does incremental codegen; only the CGUs that actually
  changed get recompiled.
- We skip the vast majority of the link: no libstd, no libc, no most
  dependencies. Just a handful of workspace rlibs + a few `.rcgu.o`s + the
  stub object.
- The stub's trampolines are tiny (8-16 bytes each) so the stub object is
  small.
- No post-link steps (strip, codesign, bundle, copy-to-device) on the
  critical path.

## Summary of CLI surface

| Subcommand | What it does |
|---|---|
| `dx serve [--hotpatch]` | The full watch→fat→thin→ws loop. |
| `dx build --fat-binary` | Produce the reference image as a standalone artifact. |
| `dx hotpatch --aslr-reference <addr>` | One-shot: read `StructuredBuildArtifacts` from stdin, produce a single patch + JumpTable on stdout. Good for experimenting or for non-Dioxus integration. |
| `dx` (as `$RUSTC_WRAPPER`) | Captures rustc args per crate. |
| `dx` (as `-C linker=dx`) | Captures linker args or proxies. |

`cli/hotpatch.rs` is the most useful entry point for understanding the flow
in isolation — it's ~100 lines and shows exactly how an input fat artifact +
a live ASLR reference become a JumpTable.
