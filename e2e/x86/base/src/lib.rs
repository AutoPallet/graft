//! "Base" stable library — functions the `app` crate calls into.
//!
//! Structured to exercise a handful of call-graph shapes so the closure
//! analysis (M0.5.d) has interesting inputs to chew on:
//!   - `compute` — leaf-ish, only depends on self
//!   - `mix`     — mid-graph, calls `compute`
//!   - `greet`   — uses std (format!/String), references libstd
//!   - `dispatch` — indirect call through a closure (`dyn Fn`)

pub fn greet(name: &str) -> String {
    format!("hello, {name}!")
}

pub fn compute(xs: &[u32]) -> u32 {
    let mut acc: u32 = 0;
    for &x in xs {
        acc = acc.wrapping_add(x.wrapping_mul(7));
    }
    acc
}

pub fn mix(xs: &[u32], salt: u32) -> u32 {
    compute(xs).wrapping_mul(salt).rotate_left(3)
}

pub fn dispatch(f: &dyn Fn(u32) -> u32, x: u32) -> u32 {
    f(x)
}

// Forwards into the C static-archive shim. `outer` calls `inner`
// across a different `.o` in the same archive, so an overlay edit
// to `inner.c` must drag `outer.o` into the closure too — the
// archive-walking case that's not exercised by Rust-only fixtures.
unsafe extern "C" {
    fn cshim_outer(x: core::ffi::c_uint) -> core::ffi::c_uint;
}

pub fn cshim(x: u32) -> u32 {
    unsafe { cshim_outer(x) }
}

// Content-degenerate mutable state: two zero-init statics plus an
// atomic, all byte-identical (or byte-less) sections. Pure content
// identity collapses them onto one trans_hash; an overlay that
// resolves them positionally without nominal identity binds distinct
// variables to ONE base address (the M2 xtensa call-to-0: TICK_COUNTER
// / ATOMIC_TICK / esp_println's TIMED_OUT aliased). `tick()` is the
// edit site for the e2e scenario — re-emitting it forces its relocs to
// the (unchanged, base-resident) statics through prune's resolution.
use core::sync::atomic::{AtomicU32, Ordering};

static mut TICK: u32 = 0;
static COUNT: AtomicU32 = AtomicU32::new(0);

pub fn tick(step: u32) -> (u32, u32) {
    let t = unsafe {
        TICK = TICK.wrapping_add(step);
        TICK
    };
    let c = COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    (t, c)
}

// Section cycle: `step_a`'s text references STEP_TABLE, and STEP_TABLE
// references `step_a` (and `step_b`) back — two sections in one SCC,
// the x86 analog of xtensa's code ↔ literal-pool cycle. If SCC members
// shared one trans_hash, base's table would record one hash at two
// addresses and positional resolution could land in the wrong section
// (the M2 bug that resolved ram_resident_step into the literal pool).
// `cycle_run` is the edit site: re-emitting it forces its reference to
// the (unchanged, base-resident) table/functions through prune.
static STEP_TABLE: [fn(u32) -> u32; 2] = [step_a, step_b];

fn step_a(x: u32) -> u32 {
    if x == 0 { 0 } else { STEP_TABLE[1](x - 1).wrapping_add(1) }
}

fn step_b(x: u32) -> u32 {
    x.wrapping_mul(3)
}

pub fn cycle_run(x: u32) -> u32 {
    STEP_TABLE[(x & 1) as usize](x).wrapping_add(0)
}

// Thread-local state, exercising the TLS resolution paths (docs/15
// mechanism (c)): `.tdata` (non-zero const init → initialized template
// bytes) and `.tbss` (zero init). `tl_step` is the edit site for the
// "reference unchanged base TLS" scenario; editing the *initializer*
// of TL_ACC exercises re-emission into the GRAFT_TLS_SLACK hole; the
// new-thread-local scenario adds a third variable in an edit. TP
// offsets are linker-computed (TPOFF relocs against graft's SHF_TLS
// map sections) — no graft-side tpoff arithmetic anywhere.
use core::cell::Cell;

thread_local! {
    static TL_ACC: Cell<u32> = const { Cell::new(40) };
    static TL_ZERO: Cell<u32> = const { Cell::new(0) };
}

pub fn tl_step(n: u32) -> (u32, u32) {
    let a = TL_ACC.with(|c| {
        c.set(c.get().wrapping_add(n));
        c.get()
    });
    let z = TL_ZERO.with(|c| {
        c.set(c.get().wrapping_add(1));
        c.get()
    });
    (a, z)
}
