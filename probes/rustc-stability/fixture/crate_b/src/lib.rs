#![no_std]

use crate_a::{a_one, a_two};

pub fn b_one(x: u32) -> u32 {
    a_one(x).wrapping_add(11)
}

pub fn b_two(x: u32, y: u32) -> u32 {
    a_two(x, y).wrapping_mul(13)
}

fn b_helper(x: u32) -> u32 {
    x.rotate_left(3)
}

pub fn b_three(x: u32) -> u32 {
    b_helper(b_one(x))
}
