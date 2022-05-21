use crate::fe25519::Fe25519;
use crate::scalar::Scalar;

// Montgomery ladder computing n*xp via repeated differential additions and constant-time
// conditional swaps.
//
// Input:
//      xp: proj. x-coordinate on Montgomery curve
//      n: Scalar (max 255-bit)
//
// Output:
//      xr: proj. x-coordinate of n*xq
pub fn ladder(xp: &Fe25519, n: &Scalar) -> Fe25519 {
    let mut x2 = Fe25519::one();
    let mut x3 = *xp;
    let mut z3 = Fe25519::one();
    let mut z2 = Fe25519::zero();
    let mut tmp0: Fe25519;
    let mut tmp1: Fe25519;
    let mut swap_bit: u8 = 0;

    for idx in (0..=254).rev() {
        let bit = ((n.0[idx >> 3] >> (idx & 7)) & 1) as u8;
        swap_bit ^= bit;
        x2.swap(&mut x3, swap_bit);
        z2.swap(&mut z3, swap_bit);
        swap_bit = bit;

        tmp0 = &x3 - &z3;
        tmp1 = &x2 - &z2;
        x2 = &x2 + &z2;
        z2 = &x3 + &z3;
        z3 = &tmp0 * &x2;
        z2 = &z2 * &tmp1;
        tmp0 = tmp1.square();
        tmp1 = x2.square();
        x3 = &z3 + &z2;
        z2 = &z3 - &z2;
        x2 = &tmp1 * &tmp0;
        tmp1 = &tmp1 - &tmp0;
        z2 = z2.square();
        z3 = tmp1.mul121666();
        x3 = x3.square();
        tmp0 = &tmp0 + &z3;
        z3 = xp * &z2;
        z2 = &tmp1 * &tmp0;
    }

    x2.swap(&mut x3, swap_bit);
    z2.swap(&mut z3, swap_bit);

    z2 = z2.invert();
    x2 = &x2 * &z2;
    x2.freeze()
}

pub fn ladder_base(n: &Scalar) -> Fe25519 {
    ladder(&Fe25519([9, 0, 0, 0, 0]), n)
}

#[cfg(test)]
mod tests {}
