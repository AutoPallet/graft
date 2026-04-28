/* Inner C function — pure arithmetic, no libc deps. Lives in its own
 * translation unit so the static archive built by build.rs has at least
 * two members and the outer→inner call traverses an archive boundary.
 */

unsigned cshim_inner(unsigned x) {
    return x * 7u + 1u;
}
