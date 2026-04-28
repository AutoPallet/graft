// Compile cshim/{outer,inner}.c into libcshim.a and tell cargo to link
// it. Two members in one archive — exercises graft's archive-walking
// path: a closure that touches `cshim_outer` must also pull `cshim_inner`
// from the same `.a`, the same way ld would resolve the cross-member
// reference at link time.
//
// Pure arithmetic, no libc deps, so the resulting .o's link cleanly
// into a musl-static binary even when produced by a glibc-host gcc.

fn main() {
    println!("cargo:rerun-if-changed=cshim/inner.c");
    println!("cargo:rerun-if-changed=cshim/outer.c");
    cc::Build::new()
        .file("cshim/inner.c")
        .file("cshim/outer.c")
        .compile("cshim");
}
