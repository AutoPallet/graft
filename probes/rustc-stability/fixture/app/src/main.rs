use std::hint::black_box;

fn main() {
    let v = black_box([1u32, 2, 3, 4, 5]);
    let a = crate_b::b_one(black_box(100));
    let b = crate_b::b_two(black_box(10), black_box(20));
    let c = crate_a::a_three(&v);
    let d = crate_b::b_three(black_box(42));
    println!("{a} {b} {c} {d}");
}
