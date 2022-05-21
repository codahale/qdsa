use crate::fe25519;
use crate::fe25519::Fe25519;
use crate::scalar::GroupScalar;

// Montgomery ladder computing n*xp via repeated differential additions and constant-time
// conditional swaps.
//
// Input:
//      xp: proj. x-coordinate on Montgomery curve
//      n: Scalar (max 255-bit)
//
// Output:
//      xr: proj. x-coordinate of n*xq
pub fn ladder(xp: &Fe25519, n: &GroupScalar) -> Fe25519 {
    let mut x2 = fe25519::one();
    let mut x3 = *xp;
    let mut z3 = fe25519::one();
    let mut z2 = fe25519::zero();
    let mut tmp0: Fe25519;
    let mut tmp1: Fe25519;
    let mut swap_bit: u8 = 0;

    for idx in (0..=254).rev() {
        let bit = ((n[idx >> 3] >> (idx & 7)) & 1) as u8;
        swap_bit ^= bit;
        fe25519::swap(&mut x2, &mut x3, swap_bit);
        fe25519::swap(&mut z2, &mut z3, swap_bit);
        swap_bit = bit;

        tmp0 = fe25519::sub(&x3, &z3); // x3 - z3;
        tmp1 = fe25519::sub(&x2, &z2); // x2 - z2;
        x2 = fe25519::add(&x2, &z2); // x2 + z2;
        z2 = fe25519::add(&x3, &z3); // x3 + z3;
        z3 = fe25519::mul(&tmp0, &x2); // tmp0 * x2;
        z2 = fe25519::mul(&z2, &tmp1); // z2 * tmp1;
        tmp0 = fe25519::square(&tmp1);
        tmp1 = fe25519::square(&x2);
        x3 = fe25519::add(&z3, &z2); // z3 + z2;
        z2 = fe25519::sub(&z3, &z2); // z3 - z2;
        x2 = fe25519::mul(&tmp1, &tmp0); // tmp1 * tmp0;
        tmp1 = fe25519::sub(&tmp1, &tmp0); // tmp1 - tmp0;
        z2 = fe25519::square(&z2);
        z3 = fe25519::mul121666(&tmp1);
        x3 = fe25519::square(&x3);
        tmp0 = fe25519::add(&tmp0, &z3); // tmp0 + z3;
        z3 = fe25519::mul(xp, &z2); // x1 * z2;
        z2 = fe25519::mul(&tmp1, &tmp0); // tmp1 * tmp0;
    }

    fe25519::swap(&mut x2, &mut x3, swap_bit);
    fe25519::swap(&mut z2, &mut z3, swap_bit);

    z2 = fe25519::invert(&z2);
    x2 = fe25519::mul(&x2, &z2); // x2 * z2;
    x2
}

pub fn ladder_base(n: &GroupScalar) -> Fe25519 {
    ladder(&[9, 0, 0, 0, 0], n)
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
    let b0 = fe25519::mul(xp, xq);
    let b1 = fe25519::mul(&fe25519::one(), &fe25519::one());
    let bzz = fe25519::square(&fe25519::sub(&b0, &b1));
    let b0 = fe25519::add(&b0, &b1);

    let b1 = fe25519::mul(xp, &fe25519::one());
    let b2 = fe25519::mul(xq, &fe25519::one());
    let bxx = fe25519::square(&fe25519::sub(&b1, &b2));

    let bxz = fe25519::add(&b1, &b2);
    let bxz = fe25519::mul(&bxz, &b0);
    let b0 = fe25519::mul(&b1, &b2);
    let b0 = fe25519::add(&b0, &b0);
    let b0 = fe25519::add(&b0, &b0);
    let b1 = fe25519::add(&b0, &b0);
    let b1 = fe25519::mul121666(&b1);
    let b0 = fe25519::sub(&b1, &b0);
    let bxz = fe25519::add(&bxz, &b0);
    let bxz = fe25519::add(&bxz, &bxz);

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
    let b0 = fe25519::square(rx);
    let b0 = fe25519::mul(&b0, bxx);
    let b1 = fe25519::mul(rx, bxz);
    let b0 = fe25519::sub(&b0, &b1);
    let b0 = fe25519::add(&b0, bzz);

    fe25519::iszero(&b0)
}

#[cfg(test)]
mod tests {}
