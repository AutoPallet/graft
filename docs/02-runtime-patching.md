# 02 — Runtime patching (the `subsecond` crate)

Status: reference research on Dioxus's Subsecond. graft does not use any
of this runtime mechanism; kept for context.

Everything in `packages/subsecond/`. This crate is what gets linked *into
your application*. It contains no code generation — all code gen happens on
the host `dx` side. The runtime's job is just:

1. Expose `call()` / `HotFn` so hot call sites can be marked.
2. Maintain a global pointer to the current `JumpTable`.
3. Provide `apply_patch()` which loads a patch library and rewrites that
   pointer.

## The `JumpTable` type

`subsecond-types/src/lib.rs:8-47`:

```rust
pub struct JumpTable {
    pub lib: PathBuf,           // path to the patch dylib
    pub map: AddressMap,        // HashMap<u64, u64> of old→new addresses
    pub aslr_reference: u64,    // addr of `main` in the *original* exe
    pub new_base_address: u64,  // addr of `main` in the *patch*
    pub ifunc_count: u64,       // wasm only
}
```

`AddressMap = HashMap<u64, u64, BuildAddressHasher>` uses a no-op hasher
(`AddressHasher`) because addresses are already unique.

The map is serializable (serde) — it travels over the devtools websocket as
JSON. On a 32-bit target all addresses are still `u64`; the runtime casts to
`u32` when doing the `transmute`. See
`subsecond/src/lib.rs:906-917` for the 32/64-bit dance.

## `HotFn` and the `HotFunction` trait

Core trick (`subsecond/src/lib.rs:845-952`):

```rust
pub trait HotFunction<Args, Marker> {
    type Return;
    type Real;                                  // fn(Args) -> Return
    fn call_it(&mut self, args: Args) -> Self::Return;
    unsafe fn call_as_ptr(&mut self, args: Args) -> Self::Return;
}

// Blanket impl for every FnMut arity (0..=9), macro-expanded:
impl<T, R, A, B, ...> HotFunction<(A, B, ...), FnNMarker> for T
where T: FnMut(A, B, ...) -> R
{
    type Real = fn(A, B, ...) -> R;

    fn call_it(&mut self, args) -> R { /* direct call */ }

    unsafe fn call_as_ptr(&mut self, args) -> R {
        if let Some(table) = get_jump_table() {
            let real = transmute_copy::<Self, Self::Real>(&self) as *const () as u64;
            if let Some(ptr) = table.map.get(&real).copied() {
                return transmute::<_, Self::Real>(ptr)(args...);
            }
        }
        self.call_it(args)
    }
}
```

`HotFn<A, M, F>` wraps a function value. On call it picks between the
trait-object path and the function-pointer path by checking
`size_of::<F>() == size_of::<fn() -> ()>()`. That's how it handles both
bare `fn`s (ZSTs that implement `Fn`) and closures that have captured state:
the former can be `transmute_copy`'d to a function pointer, the latter cannot
and fall back to `call_it` (which itself may be swapped later because
`call_it` is a monomorphized trait method that *does* get its own address in
the jump table).

## `call()` and the unwind machinery

`subsecond/src/lib.rs:250-271`:

```rust
pub fn call<O>(mut f: impl FnMut() -> O) -> O {
    if !cfg!(debug_assertions) { return f(); }
    let mut hotfn = HotFn::current(f);
    loop {
        match std::panic::catch_unwind(AssertUnwindSafe(|| hotfn.call(()))) {
            Ok(res) => return res,
            Err(err) => {
                if err.downcast_ref::<HotFnPanic>().is_none() {
                    std::panic::resume_unwind(err);
                }
                // else: our own signal that this call is stale; retry the loop
            }
        }
    }
}
```

When the patch engine decides a function's invariants have changed beyond
in-place patching (e.g. because a caller's stack frame would be wrong), it
emits a `HotFnPanic`. `call` catches that panic, drops the closure (running
all `Drop` impls on closure state), and re-enters `hotfn.call(())` which
will now look up the new pointer in the (freshly updated) jump table.

**This is the entire "rewind to the nearest clean entry point" mechanism.**
There is no stack unwinder of our own — it's literally just Rust's
`catch_unwind`. This is also why the doc warns WASM loses this behavior:
wasm32 unwinds are not real unwinds.

## `apply_patch` — the one unsafe ritual

`subsecond/src/lib.rs:498-547` (native) / `:549-681` (wasm).

Native flow:

```rust
pub unsafe fn apply_patch(mut table: JumpTable) -> Result<(), PatchError> {
    let lib = Box::leak(Box::new(libloading::Library::new(&table.lib)?));

    // old_offset = where `main` lives *now* in our process
    //              minus where `main` lived when dx recorded it
    let old_offset = aslr_reference() - table.aslr_reference as usize;

    // new_offset = where the patch was *linked to expect* main
    //              minus where it actually loaded
    let new_offset = lib.get::<*const ()>(b"main")?.try_as_raw_ptr()?
        .wrapping_byte_sub(table.new_base_address as usize) as usize;

    // Rebase every entry in the map
    table.map = table.map.iter().map(|(k, v)| {
        ((*k as usize + old_offset) as u64,
         (*v as usize + new_offset) as u64)
    }).collect();

    commit_patch(table);  // atomic store into APP_JUMP_TABLE
}
```

`aslr_reference()` (`:709-743`) resolves the address of `main` *at runtime*
via `dlsym(RTLD_DEFAULT, "main")` / `GetProcAddress`. Together with the
`table.aslr_reference` — which is `main`'s address as seen by the linker at
*fat build* time — this lets dx record addresses using its compile-time view
and have them correct in the process's view after ASLR slide.

Why `main`? Because it's guaranteed to exist, its relative position to
everything else in the binary never changes, and both the host and the
running program can always find it. Any other globally-visible non-weak
symbol could in principle be used as the anchor.

`commit_patch` (`:308-321`): a `Box::leak` + atomic-store of the new table
plus firing registered `HOTRELOAD_HANDLERS` (these are where frameworks
like Dioxus throw out their VDOM state so struct-layout changes don't
segfault).

## The WASM path is different

- No ASLR, so `aslr_reference = 0`.
- No dlopen: must `fetch()` the patch bytes, grow the memory, grow the
  ifunc table, and call `WebAssembly.instantiate()` with carefully
  constructed imports that feed back the main module's memory, stack,
  `__indirect_function_table`, and import placeholders for TLS/stack
  globals.
- Entries in the `map` are ifunc indices, not addresses. After loading the
  patch the runtime adds the new `table_base` (where the patch's functions
  land in the shared ifunc table) to each entry.
- After load, the runtime calls three synthetic functions in the patch:
  `__wasm_apply_data_relocs`, `__wasm_apply_global_relocs`,
  `__wasm_call_ctors`.

`:549-681`. For a microcontroller port we can ignore almost all of this
(except the observation that treating "addresses" as opaque indices into a
separate table works when the real address space isn't loadable).

## Interaction with frameworks: handlers

`register_handler(Arc<dyn Fn()>)` stores callbacks; `commit_patch` runs them
synchronously under the mutex. Framework integrations use this to:

- Tear down and re-build the VDOM / scene graph.
- Invalidate memoization caches keyed on function pointers.
- Re-register routes (so `Router::get("/", handler)` re-picks the new
  handler).

For a game-loop / embedded-style app you'd typically register a handler that
flags a "restart" boolean checked at the top of the main loop.

## What the runtime does NOT do

- No symbol resolution. It trusts the jump table.
- No linking. It trusts `dlopen`.
- No relocation beyond the two `_offset` adds above. The patch itself must
  be position-independent and self-contained — that's the CLI's job.
