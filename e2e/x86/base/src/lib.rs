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
