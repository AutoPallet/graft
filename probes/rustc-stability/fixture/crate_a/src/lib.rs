#![no_std]

pub fn a_one(x: u32) -> u32 {
    x.wrapping_mul(3).wrapping_add(7)
}

pub fn a_two(x: u32, y: u32) -> u32 {
    a_one(x).wrapping_add(y)
}

fn a_helper(x: u32) -> u32 {
    x ^ 0xDEAD_BEEF
}

pub fn a_three(v: &[u32]) -> u32 {
    let mut acc: u32 = 0;
    let mut i = 0;
    while i < v.len() {
        acc = acc.wrapping_add(a_helper(v[i]));
        i += 1;
    }
    acc
}
