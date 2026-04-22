# 05 — Adapting Subsecond to ESP32

This is the part you actually care about. Split into:

1. What maps cleanly.
2. What breaks and why.
3. A concrete port plan, ordered by risk.

## First: which ESP32?

The ESP32 family ships two ISAs, and the port is meaningfully different
for each:

| Chip | ISA | Rust target | Notes |
|---|---|---|---|
| ESP32 (classic), S2, S3 | Xtensa LX6/LX7 | `xtensa-esp32-none-elf` etc. | Needs a custom LLVM fork (`esp-rs/rust`). `object` crate doesn't know xtensa. |
| ESP32-C3, C6, H2, P4 | RISC-V 32-bit (IMAC) | `riscv32imac-unknown-none-elf` / `riscv32imc-*` | Upstream Rust. `object` crate has riscv support. |

**Recommendation**: if you have a choice, start with a RISC-V variant
(C3/C6). Everything downstream — stub trampoline assembly, object file
parsing, linker support — is easier.

## What maps cleanly

The runtime ideas port almost verbatim:

- **`JumpTable`** (HashMap<u64, u64>) is target-agnostic. On a 32-bit
  target the top 32 bits are always zero; just cast at lookup time, which
  is already how `subsecond` handles `target_pointer_width = "32"`
  (`subsecond/src/lib.rs:906-929`).
- **`HotFn` / `call()`** work without modification. The function-pointer
  lookup is pure arithmetic; `catch_unwind` is the only piece that
  requires unwinding, and Rust's xtensa/riscv targets do support panic =
  "unwind" if you enable it — though most embedded projects set
  `panic = "abort"`. More on that below.
- **Undefined-symbol stub concept** — hard-coded absolute-address jump
  trampolines embedded in an object file — is exactly what you want on a
  chip with no dynamic linker. In fact it's a better fit on ESP32 than
  on desktop: there is **no ASLR**, so the "rebase by `main` delta" step
  collapses to a no-op. The absolute addresses compiled into the stubs
  *are* the addresses the patch should call.
- **Fat build → thin build pipeline** is independent of target. The
  captured rustc args + replay-then-link approach works anywhere rustc
  works.

## What breaks, and why

### 1. There is no `dlopen`

ESP-IDF / `esp-rs` don't ship a dynamic linker. `libloading` won't link.
The patch has to be loaded by *you* into a RAM region where code can be
executed, with manual relocation.

Three sub-problems:

- **Where does the patched code live?** Flash (XIP from IROM) is
  effectively immutable at runtime without OTA operations. IRAM and DRAM
  are candidates; on ESP32-S3 there's additionally PSRAM but you can't
  execute from PSRAM by default. **Answer**: reserve a sized IRAM region
  at link time for patches. Size it generously (32–128 KB).
- **Which relocation model?** Desktop uses `-shared` and applies
  relocations at `dlopen` time. We need either:
  - (a) **Fully absolute code**: patch object has all call targets
    resolved at link time, plus we link it *at the known load address*
    of our patch RAM region. Simplest, but each new patch has to be
    linked against the specific load address.
  - (b) **Position-independent code**: compile patch with
    `relocation-model=pic` (RISC-V supports this; Xtensa less well),
    apply a few relocation types at load time.
- **How do patches reference the fat binary's code and data?** Same
  trick Dioxus uses: undefined-symbol stubs with absolute-address jump
  trampolines. Both RISC-V and Xtensa can do this trivially.

### 2. `object` crate doesn't know Xtensa

Looking at `build/patch.rs:884-889`:

```rust
match triple.architecture {
    Architecture::Aarch64(_) => object::Architecture::Aarch64,
    Architecture::Wasm32 => object::Architecture::Wasm32,
    Architecture::X86_64 => object::Architecture::X86_64,
    _ => return Err(PatchError::UnsupportedPlatform(triple.to_string())),
}
```

We'd need to:

- Add a RISC-V arm to this match (`object` already knows
  `object::Architecture::Riscv32`). Straightforward.
- Add stub-asm generation for RISC-V. See below.
- For Xtensa: `object` crate has no Xtensa ELF support. Either vendor
  enough ELF parsing/writing to emit an Xtensa relocatable, or use
  `goblin` which does have Xtensa. Bigger lift.

### 3. Stub trampolines need new ISAs

Absolute-address jump trampoline to synthesize. RISC-V 32-bit:

```
# Load 32-bit immediate into t0, then JALR
lui   t0, %hi(abs_addr)    # 0b0000000000000000000_00101_0110111 | imm[31:12]<<12
addi  t0, t0, %lo(abs_addr) # or use AUIPC+JALR for PIC variant
jalr  x0, 0(t0)            # jump, don't save return addr (tail call)
```

Three 4-byte instructions = 12 bytes. Encoding is simple.

Xtensa is more awkward because of its windowed registers and
variable-length encoding; the `j.l` (long jump) instruction takes an 18-bit
absolute offset and isn't sufficient. You'd probably emit a literal-pool
load:

```
       l32r  a8, .Laddr
       jx    a8
.Laddr: .word abs_addr
```

`l32r` is PC-relative with a 16-bit offset; the literal needs to be
within range, which means emitting it in a `.rodata` section of the
same patch — fine, since the patch object gets linked as a unit.

### 4. Shipping the patch to the device

No filesystem. Options, from easiest to most work:

- **Wired**: UART or USB-CDC. Cheap and stupid: send the raw .o/.bin bytes
  with a framed protocol (length prefix + CRC). For a 20-200 KB patch at
  921600 baud that's sub-second.
- **Wifi**: TCP or HTTP(S) PUT. Requires the device be connected.
- **JTAG / SWD**: only useful if you already have a probe and the RAM
  region is writable via the debug interface. Lets you keep the existing
  breakpoint + resume workflow.

The wire protocol can mirror Dioxus's `HotReloadMsg`, but with `jump_table`
inlined (no filesystem path) and the patch *bytes* either in the same
message or fetched separately via a follow-up frame.

### 5. `catch_unwind` / `panic = "unwind"`

Dioxus uses the panic-and-retry trick to unwind to the nearest enclosing
`call()`. If your project uses `panic = "abort"` (typical for ESP32), that
mechanism does nothing and every patch is effectively "call the new
function at the inner-most hot point and hope state is compatible."

Two options:

- Enable `panic = "unwind"` in dev profile. `esp-rs` supports it on RISC-V
  targets; on Xtensa it's experimental. This costs code size.
- Live without it: require all edits to occur strictly *within* a
  `call()`-wrapped function. This is a real constraint but not a crippling
  one for a firmware — edit the loop body, not the initializer.

### 6. Statics, globals, heap state

Same caveats as desktop but more punishing:

- Peripheral handles (e.g. `esp_hal::gpio::Output<'static>`) are almost
  never safe to re-instantiate on patch. Treat them as `register_handler`
  victims: on patch, **don't** rebuild them — keep them in `static`s that
  persist across the patch, and have the hot code re-read them by name.
- Heap allocators: okay as long as the allocator type doesn't change
  layout. Don't edit the allocator's code.
- TLS: not meaningful on bare-metal single-core/multi-core-without-threads
  setups. Ignore.

### 7. Cache coherence

When we load new instructions into IRAM, we must invalidate the
instruction cache before executing them. ESP32 has an instruction cache;
on RISC-V cores you need a `fence.i`, on Xtensa a `isync` (and possibly
`dhwbi` if the region is cached for data writes). Trivially one function
call into `esp_hal` but *must not be forgotten*, or you'll hit ghost calls
to old code at random.

## Port plan, ordered

Milestones in escalating difficulty. Stop at whatever level is "good
enough" for your use case.

### M0 — Proof that the runtime links (1-2 days)

Compile `subsecond` for your target with `libloading` gated out. The apply
side is shot, but `call()` / `HotFn` / `APP_JUMP_TABLE` should compile
no_std-ish. If not, vendor the crate and strip it down to the bits that
matter (essentially `HotFunction` macro + `APP_JUMP_TABLE` + a new
`apply_patch_from_bytes(&[u8])`).

### M1 — Manual, on-device one-shot patch (1 week)

Skip the CLI entirely. Hand-craft a patch object file, flash it to a
reserved IRAM region at a known address, hand-craft a `JumpTable`, call a
stripped-down `apply_patch`. This proves the in-process mechanism works on
your silicon. Target: swap a single function body by hand.

### M2 — CLI that produces a patch for one architecture (2-3 weeks)

Fork `dx` or start a minimal driver. Reuse as much of
`build/patch.rs`'s `create_undefined_symbol_stub` as possible:

- Add a RISC-V arm (or Xtensa if you have to).
- Instead of `dlopen`-style `.so`, produce a flat blob suitable for
  direct upload — either a true relocatable `.o` that you relocate
  on-device, or a fully-linked blob against a known load address.
- Skip the websocket. UART transport first.
- Reuse `rustcwrapper.rs` and `link.rs` as-is; they don't care about
  target.
- Reuse `HotpatchModuleCache::new` on the fat ELF.

### M3 — File watcher + iterative patches (1 week)

Wrap M2 in a `notify`-based loop. This is the Dioxus `serve/` equivalent
and is target-agnostic.

### M4 — Framework integration (open-ended)

Decide where `subsecond::call(|| …)` boundaries go in your firmware:

- Main loop body — almost always.
- Input/event handlers.
- Network handlers.
- State-machine transitions.

Register a `subsecond::register_handler` that tears down anything whose
layout might have changed (task queues, animation state).

### Stretch: PIC patches

Compile patches with `relocation-model=pic` so they can be loaded to any
RAM address. Requires implementing a few relocation types
(`R_RISCV_CALL`, `R_RISCV_HI20`, `R_RISCV_LO12_I`, etc.) in the on-device
loader. Makes multi-patch without reflashing feasible.

## Risks and unknowns

- **Xtensa tooling**: the Rust-for-Xtensa LLVM is a separate fork; some
  `-C` flags may behave differently. The fat build's `--export-dynamic`
  etc. need validation.
- **Monomorphization explosion**: Subsecond only patches the tip crate
  reliably because dep code gen is non-deterministic under rustc. On
  firmware codebases that lean heavily on generic drivers (`embedded-hal`
  trait everywhere) you will eat a lot of changed CGUs per edit.
- **Code-size budget for stubs**: each undefined symbol = 12-16 bytes of
  IRAM. A large patch could reference thousands of symbols; at 16B ×
  3000 = 48 KB. IRAM is typically 128 KB. Monitor this.
- **Flash-side constants**: if a patched function references a new `&str`
  literal, the literal lives in the patch, not the fat binary's
  `.rodata`. That's fine as long as the patch RAM region holds ro-data
  too (it does if you link it as a complete blob).
- **Interrupts and patches**: applying a patch while an ISR is running
  one of the replaced functions is a crash. Easy mitigation: disable
  interrupts across `apply_patch`, or gate patching on a known-safe
  quiescent point in the main loop.

## What to steal vs. write fresh

| Piece | Verdict |
|---|---|
| `subsecond::{call, HotFn, HotFunction}` | **Reuse verbatim.** |
| `subsecond::apply_patch` | Rewrite — it's ~40 lines and the `dlopen` half is replaced. |
| `subsecond-types::JumpTable` | **Reuse verbatim.** |
| `HotpatchModuleCache` | Reuse the symbol-table half; TLS/wasm bits drop. |
| `create_undefined_symbol_stub` | Reuse structure; add RISC-V/Xtensa arms. |
| `rustcwrapper.rs` | **Reuse verbatim.** |
| `cli::link.rs` (the shim) | **Reuse verbatim** for NoLink mode. |
| `build/link.rs` (thin link) | Reuse; swap the final linker invocation for one that targets your chip's format. |
| `serve/` websocket | Don't port — UART/TCP frame protocol instead. |
| `devtools-types::HotReloadMsg` | Simplify — keep `jump_table`, drop the RSX/asset fields, add `patch_bytes: Vec<u8>`. |

The leverage is enormous: well over half of the Dioxus code is directly
reusable, and the parts that need rewriting (`apply_patch`, stub asm for a
new ISA, transport) are small and well-scoped.
