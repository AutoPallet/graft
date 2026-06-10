use std::hint::black_box;

fn main() {
    let msg = base::greet("graft");
    let data: &[u32] = &[1, 2, 3, 4, 5];
    let sum = base::compute(data);
    let mixed = base::mix(data, black_box(17));
    let doubled = base::dispatch(&|x| x.wrapping_mul(2), black_box(21));
    let cshim = base::cshim(black_box(10));
    // Two rounds so aliased mutable statics are detectable: if TICK and
    // COUNT shared one address, the atomic's fetch_add would observe
    // TICK's writes and the pairs would diverge from (1,1),(2,2).
    let (t1, c1) = base::tick(black_box(1));
    let (t2, c2) = base::tick(black_box(1));
    let cyc_even = base::cycle_run(black_box(4)); // step_a recurses through the table
    let cyc_odd = base::cycle_run(black_box(7)); // step_b: 7*3

    println!("{msg}");
    println!("sum = {sum}");
    println!("mixed = {mixed}");
    println!("doubled = {doubled}");
    println!("cshim = {cshim}");
    println!("ticks = {t1},{c1},{t2},{c2}");
    println!("cycle = {cyc_even},{cyc_odd}");
}
