use std::hint::black_box;

fn main() {
    let msg = base::greet("graft");
    let data: &[u32] = &[1, 2, 3, 4, 5];
    let sum = base::compute(data);
    let mixed = base::mix(data, black_box(17));
    let doubled = base::dispatch(&|x| x.wrapping_mul(2), black_box(21));

    println!("{msg}");
    println!("sum = {sum}");
    println!("mixed = {mixed}");
    println!("doubled = {doubled}");
}
