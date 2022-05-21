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

/*
 * Three biquadratic forms B_XX, B_XZ and B_ZZ
 * in the coordinates of xp and xq
 *
 * Input:
 *      xp: proj. x-coordinate on Montgomery curve
 *      xq: proj. x-coordinate on Montgomery curve
 *
 * Output:
 *      bZZ: Element B_ZZ of fe25519
 *      bXZ: Element B_XZ of fe25519
 *      bXX: Element B_XX of fe25519
 */
pub fn b_values(xp: &Fe25519, xq: &Fe25519) -> (Fe25519, Fe25519, Fe25519) {
    let b0 = xp * xq;
    let b1 = &Fe25519::one() * &Fe25519::one();
    let bzz = (&b0 - &b1).square();
    let b0 = &b0 + &b1;

    let b1 = xp * &Fe25519::one();
    let b2 = xq * &Fe25519::one();
    let bxx = (&b1 - &b2).square();

    let bxz = &b1 + &b2;
    let bxz = &bxz * &b0;
    let b0 = &b1 * &b2;
    let b0 = &b0 + &b0;
    let b0 = &b0 + &b0;
    let b1 = &b0 + &b0;
    let b1 = b1.mul121666();
    let b0 = &b1 - &b0;
    let bxz = &bxz + &b0;
    let bxz = &bxz + &bxz;

    (bzz, bxz, bxx)
}

// Verify whether B_XXrx^2 - B_XZrx + B_ZZ = 0
//
// Input:
//      bZZ: Biquadratic form B_ZZ
//      bXZ: Biquadratic form B_XZ
//      bXX: Biquadratic form B_XX
//      rx: affine x-coordinate on Montgomery curve
//
// Output:
//      1 if B_XXrx^2 - B_XZrx + B_ZZ = 0,
//      0 otherwise
#[must_use]
pub fn check(bzz: &Fe25519, bxz: &Fe25519, bxx: &Fe25519, rx: &Fe25519) -> bool {
    let b0 = rx.square();
    let b0 = &b0 * bxx;
    let b1 = rx * bxz;
    let b0 = &b0 - &b1;
    let b0 = &b0 + bzz;
    b0.is_zero()
}

#[cfg(test)]
mod tests {}
