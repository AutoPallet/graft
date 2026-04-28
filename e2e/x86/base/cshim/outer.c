/* Outer C function — calls into a different .o in the same archive.
 * The cross-member call exercises graft's archive-walking: pulling
 * outer.o into the closure must also pull inner.o, the same way ld
 * would resolve the inner reference at link time.
 */

unsigned cshim_inner(unsigned x);

unsigned cshim_outer(unsigned x) {
    return cshim_inner(x) + cshim_inner(x + 1u);
}
