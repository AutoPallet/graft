# 01 — End-to-end architecture

A single mental model for how Subsecond turns a Rust code edit into a running
patch in under a second.

## The cast

```
┌──────────────────────── dx serve (host) ────────────────────────┐
│                                                                 │
│   cargo ─(RUSTC_WRAPPER=dx)──► rustc ─(linker=dx)──► object     │
│                │                                      files     │
│                │  (captures args/envs to               │        │
│                │   target/dx-rustc/<crate>.json)       │        │
│                ▼                                       ▼        │
│            change-detect ─────► thin link (link.rs)             │
│            (notify crate)       ├─ replay captured rustc        │
│                                 │  for each changed crate       │
│                                 ├─ gather fresh .rcgu.o's       │
│                                 ├─ build undefined-symbol       │
│                                 │  "stub.o" with absolute-addr  │
│                                 │  jump trampolines             │
│                                 └─ invoke real linker           │
│                                     → libpatch-<ts>.so          │
│                                                │                │
│            ┌─── subsecond-types::JumpTable ────┘                │
│            │    (old addr → new addr hashmap)                   │
│            ▼                                                    │
│         websocket ───── HotReloadMsg(JumpTable + patch path) ───┼──►
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                                                                  │
┌───────────────────────── running app ───────────────────────────┤
│                                                                 │
│   subsecond::call(|| body())  ──┐                               │
│                                 │                               │
│                                 ▼                               │
│                         APP_JUMP_TABLE.load()                   │
│                         if Some(new) { transmute & call new }   │
│                         else call original                      │
│                                                                 │
│   devtools websocket handler ─► apply_patch(jump_table):        │
│                                   dlopen(patch.so)              │
│                                   lookup `main` for new_base    │
│                                   rebase each (old,new) addr    │
│                                     using ASLR slide            │
│                                   store new table in AtomicPtr  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## The one big idea: a jump table, not memory rewriting

Tools like [`detour`](https://crates.io/crates/detour) hot-patch by
overwriting the first few bytes of a live function with a `jmp` — dangerous,
platform-specific, and constantly at war with W^X and CFI. Subsecond never
touches process memory. Every hot call site does one `Relaxed` atomic load of
a pointer to a `JumpTable` (a `HashMap<u64, u64>` of old→new function
addresses). If the old function's address is in the table, it `transmute`s
the new pointer to the right fn type and tail-calls it. If not, it calls the
original inline.

See `packages/subsecond/subsecond/src/lib.rs:279` for `APP_JUMP_TABLE` and
`:870-938` for the `HotFunction::call_as_ptr` macro that implements the
trampoline per arity.

## The three faces of `dx`

The same `dx` binary plays **three roles** in one build:

1. **The serve/build driver.** You invoked `dx serve`. It spawns cargo.
2. **A rustc wrapper** (when cargo invokes `$RUSTC_WRAPPER`). Captures the
   exact args and env for every workspace crate to
   `target/dx-rustc/<crate>.{lib,bin}.json` so we can replay rustc
   verbatim later, without cargo. See `rustcwrapper.rs:53-94`.
3. **A linker shim** (when rustc invokes `-C linker=dx`). In `NoLink` mode it
   dumps the linker args to a file and writes a stub object so rustc is
   happy; in `BaseLink` mode it proxies to a chosen real linker. See
   `cli/link.rs:30-50, 111-242`.

This nested impersonation is how Dioxus gets around the fact that rustc does
not expose "give me the object files and let me do the final link myself" as
a first-class API. You intercept cargo's calls to rustc, then rustc's calls
to ld, and now you own the whole pipeline.

## Two build modes that matter

`BuildMode` in `cli/src/build/request.rs`:

- **`Fat`**: the initial full build. Everything is compiled, all symbols
  exported, nothing GC'd. The result is the binary the user actually runs.
  This is the reference image.
- **`Thin`**: a patch build. Given an `aslr_reference` from the running app,
  a set of `modified_crates`, and the captured `WorkspaceRustcArgs` from the
  fat build: replay rustc for changed crates, generate a tiny relocatable
  `.so`/`.dylib` that references the fat binary's symbols by absolute
  address.

Only the "tip" crate (the one containing `main.rs`) and its dependencies can
be patched. Workspace dependents are pulled in transitively via the
`modified_crates` set which is cumulative — every patch contains **every**
change since the fat build. This is how Dioxus gets away with "no patch
lineage" — the latest patch always fully supersedes previous ones.

## What `call()` actually provides

```rust
subsecond::call(|| {
    // everything here is hot
});
```

- If you edit code **inside** the closure and it lives in the tip crate's
  function, the new compilation slots into the jump table and the next entry
  to `call` redirects.
- If you edit code **outside** the closure (a function further up the stack,
  a type layout, etc.), `call`'s wrapped `catch_unwind` catches a
  `HotFnPanic`, which is Dioxus's signal that state above is stale — the
  stack unwinds to the next enclosing `call()`, which then retries.
- This gives framework authors a graceful way to scope "stateful" vs
  "restartable" regions without writing a full framework integration.

## Scope boundaries and limitations

Fundamentally:

- **Only tip-crate code is patchable.** Workspace lib-then-bin setups
  (lib.rs + main.rs in the same crate) confuse rustc's non-deterministic
  codegen and won't patch reliably.
- **Structs can't change layout.** Existing instances keep the old size
  and alignment; calling new code with a changed struct is UB. Frameworks
  are expected to throw state out on patch.
- **Statics are preserved across patches** but their destructors never run
  and initializer changes are ignored. Thread-locals in the tip crate reset
  to their init value on every patch (open issue).
- **Debug only.** `cfg!(debug_assertions)` gates the whole thing;
  `subsecond::call` becomes a direct call in release.

All of the above lives in the doc comment at
`packages/subsecond/subsecond/src/lib.rs:1-230`.
