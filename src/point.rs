use fe25519::Fe25519;

use crate::fe25519;
use crate::scalar::GroupScalar;

#[derive(Clone, Copy, Debug, Default)]
pub struct Point {
    x: Fe25519,
    z: Fe25519,
}

// verified
fn swap(a: &mut Point, b: &mut Point, swap: u8) {
    fe25519::swap(&mut a.x, &mut b.x, swap);
    fe25519::swap(&mut a.z, &mut b.z, swap);
}

// Simultaneous xDBL and xADD operation on the Montgomery curve.
//
// Input:
//      xp: proj. x-coordinate on Montgomery curve
//      xq: proj. x-coordinate on Montgomery curve
//      xd: affine x-coordinate of difference xp-xq
//
// Output:
//      xp: proj. x-coordinate of 2*xp
//      xq: proj. x-coordinate of xp+xq
// verified
fn x_dbl_add(p: &mut Point, q: &mut Point, xd: &Fe25519) {
    let mut b0 = fe25519::add(&p.x, &p.z);
    let mut b1 = fe25519::sub(&p.x, &p.z);
    p.x = fe25519::add(&q.x, &q.z);
    p.z = fe25519::sub(&q.x, &q.z);
    q.x = fe25519::mul(&p.z, &b0);
    p.z = fe25519::mul(&p.x, &b1);
    p.x = fe25519::add(&p.z, &q.x);
    q.z = fe25519::sub(&q.x, &p.z);
    q.x = fe25519::square(&p.x);
    p.x = fe25519::square(&q.z);
    q.z = fe25519::mul(&p.x, xd);
    p.x = fe25519::square(&b0);
    b0 = fe25519::square(&b1);
    p.z = fe25519::sub(&p.x, &b0);
    p.x = fe25519::mul(&b0, &p.x);
    b1 = fe25519::mul121666(&p.z);
    b1 = fe25519::add(&b1, &b0);
    p.z = fe25519::mul(&b1, &p.z);
}

// Montgomery ladder computing n*xp via repeated differential additions and constant-time
// conditional swaps.
//
// Input:
//      xp: proj. x-coordinate on Montgomery curve
//      xpw: affine x-coordinate of xp
//      n: Scalar (max 255-bit)
//
// Output:
//      xr: proj. x-coordinate of n*xq
// verified
pub fn ladder(xp: &Point, xpw: &Fe25519, n: &GroupScalar) -> Point {
    let mut xr = Point::default();
    let mut xp = *xp;
    let mut bit = 0;
    let mut prevbit = 0;
    xr.x = fe25519::one();
    xr.z = fe25519::zero();

    for i in (0..=254).rev() {
        bit = (n[i >> 3] >> (i & 7)) & 1;
        let b = bit ^ prevbit;
        prevbit = bit;

        swap(&mut xr, &mut xp, b as u8);
        x_dbl_add(&mut xr, &mut xp, xpw);
    }

    swap(&mut xr, &mut xp, bit as u8);

    xr
}

// verified
pub fn ladder_base(n: &GroupScalar) -> Point {
    let base_x = [9, 0, 0, 0, 0];
    let base = Point {
        x: base_x,
        z: fe25519::one(),
    };
    ladder(&base, &base_x, n)
}

// Compress from projective representation (X : Z) to affine x = X*Z^{p-2}, where p = 2^255-19
//
// Input:
//      xp: proj. x-coordinate (X : Z)
//
// Output:
//      r: affine x-coordinate x = X*Z^{p-2}
// verified
pub fn compress(xp: &Point) -> Fe25519 {
    fe25519::freeze(&fe25519::mul(&xp.x, &fe25519::invert(&xp.z)))
}

// Decompress from affine representation x to projective (x : 1)
//
// Input:
//      r: affine x-coordinate x
//
// Output:
//      xp: proj. x-coordinate (x : 1)
// verified
pub fn decompress(r: &Fe25519) -> Point {
    Point {
        x: *r,
        z: fe25519::one(),
    }
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
pub fn b_values(xp: &Point, xq: &Point) -> (Fe25519, Fe25519, Fe25519) {
    let b0 = fe25519::mul(&xp.x, &xq.x);
    let b1 = fe25519::mul(&xp.z, &xq.z);
    let bzz = fe25519::square(&fe25519::sub(&b0, &b1));
    let b0 = fe25519::add(&b0, &b1);

    let b1 = fe25519::mul(&xp.x, &xq.z);
    let b2 = fe25519::mul(&xq.x, &xp.z);
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
