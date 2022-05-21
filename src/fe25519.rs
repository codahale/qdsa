use fiat_crypto::curve25519_64::*;
use subtle::ConstantTimeEq;

pub type Fe25519 = [u64; 5];

#[inline]
pub fn swap(a: &mut Fe25519, b: &mut Fe25519, swap: u8) {
    // SAFETY: This is a part of fiat input bounds.
    assert!(swap == 1 || swap == 0);

    let tmp_x = *a;
    let tmp_y = *b;

    fiat_25519_selectznz(a, swap, &tmp_x, &tmp_y);
    fiat_25519_selectznz(b, swap, &tmp_y, &tmp_x);
}

#[inline]
pub fn freeze(r: &Fe25519) -> Fe25519 {
    let mut ret = Default::default();
    fiat_25519_carry(&mut ret, r);
    ret
}

#[inline]
pub fn unpack(x: &[u8; 32]) -> Fe25519 {
    let mut ret = Default::default();
    let mut x = *x;
    x[31] &= 127;
    fiat_25519_from_bytes(&mut ret, &x);
    freeze(&ret)
}

#[inline]
pub fn pack(x: &Fe25519) -> [u8; 32] {
    let mut ret = Default::default();
    fiat_25519_to_bytes(&mut ret, x);
    ret
}

#[inline]
pub fn iszero(x: &Fe25519) -> bool {
    pack(x).ct_eq(&[0u8; 32]).into()
}

pub const fn one() -> Fe25519 {
    [1, 0, 0, 0, 0]
}

pub const fn zero() -> Fe25519 {
    [0, 0, 0, 0, 0]
}

#[inline]
pub fn add(x: &Fe25519, y: &Fe25519) -> Fe25519 {
    let mut ret = Default::default();
    fiat_25519_add(&mut ret, x, y);
    freeze(&ret)
}

#[inline]
pub fn sub(x: &Fe25519, y: &Fe25519) -> Fe25519 {
    let mut ret = Default::default();
    fiat_25519_sub(&mut ret, x, y);
    freeze(&ret)
}

#[inline]
pub fn mul121666(x: &Fe25519) -> Fe25519 {
    let mut ret = Default::default();
    fiat_25519_carry_scmul_121666(&mut ret, x);
    freeze(&ret)
}

#[inline]
pub fn mul(x: &Fe25519, y: &Fe25519) -> Fe25519 {
    let mut ret = Default::default();
    fiat_25519_carry_mul(&mut ret, x, y);
    freeze(&ret)
}

#[inline]
pub fn square(x: &Fe25519) -> Fe25519 {
    let mut ret = Default::default();
    fiat_25519_carry_square(&mut ret, x);
    freeze(&ret)
}

pub fn invert(x: &Fe25519) -> Fe25519 {
    /* 2 */
    let z2 = square(x);
    /* 4 */
    let t1 = square(&z2);
    /* 8 */
    let t0 = square(&t1);
    /* 9 */
    let z9 = mul(&t0, x);
    /* 11 */
    let z11 = mul(&z9, &z2);
    /* 22 */
    let t0 = square(&z11);
    /* 2^5 - 2^0 = 31 */
    let z2 = mul(&t0, &z9);

    /* 2^6 - 2^1 */
    let t0 = square(&z2);
    /* 2^7 - 2^2 */
    let t1 = square(&t0);
    /* 2^8 - 2^3 */
    let t0 = square(&t1);
    /* 2^9 - 2^4 */
    let t1 = square(&t0);
    /* 2^10 - 2^5 */
    let t0 = square(&t1);
    /* 2^10 - 2^0 */
    let z2 = mul(&t0, &z2);

    /* 2^11 - 2^1 */
    let mut t0 = square(&z2);
    /* 2^12 - 2^2 */
    let mut t1 = square(&t0);
    /* 2^20 - 2^10 */
    for _ in (2..10).step_by(2) {
        t0 = square(&t1);
        t1 = square(&t0);
    }
    /* 2^20 - 2^0 */
    let z9 = mul(&t1, &z2);

    /* 2^21 - 2^1 */
    let mut t0 = square(&z9);
    /* 2^22 - 2^2 */
    let mut t1 = square(&t0);
    /* 2^40 - 2^20 */
    for _ in (2..20).step_by(2) {
        t0 = square(&t1);
        t1 = square(&t0);
    }
    /* 2^40 - 2^0 */
    let t0 = mul(&t1, &z9);

    /* 2^41 - 2^1 */
    let mut t1 = square(&t0);
    /* 2^42 - 2^2 */
    let mut t0 = square(&t1);
    /* 2^50 - 2^10 */
    for _ in (2..10).step_by(2) {
        t1 = square(&t0);
        t0 = square(&t1);
    }
    /* 2^50 - 2^0 */
    let z2 = mul(&t0, &z2);

    /* 2^51 - 2^1 */
    let mut t0 = square(&z2);
    /* 2^52 - 2^2 */
    let mut t1 = square(&t0);
    /* 2^100 - 2^50 */
    for _ in (2..50).step_by(2) {
        t0 = square(&t1);
        t1 = square(&t0);
    }
    /* 2^100 - 2^0 */
    let z9 = mul(&t1, &z2);

    /* 2^101 - 2^1 */
    let mut t1 = square(&z9);
    /* 2^102 - 2^2 */
    let mut t0 = square(&t1);
    /* 2^200 - 2^100 */
    for _ in (2..100).step_by(2) {
        t1 = square(&t0);
        t0 = square(&t1);
    }
    /* 2^200 - 2^0 */
    let t1 = mul(&t0, &z9);

    /* 2^201 - 2^1 */
    let mut t0 = square(&t1);
    /* 2^202 - 2^2 */
    let mut t1 = square(&t0);
    /* 2^250 - 2^50 */
    for _ in (2..50).step_by(2) {
        t0 = square(&t1);
        t1 = square(&t0);
    }
    /* 2^250 - 2^0 */
    let t0 = mul(&t1, &z2);

    /* 2^251 - 2^1 */
    let t1 = square(&t0);
    /* 2^252 - 2^2 */
    let t0 = square(&t1);
    /* 2^253 - 2^3 */
    let t1 = square(&t0);
    /* 2^254 - 2^4 */
    let t0 = square(&t1);
    /* 2^255 - 2^5 */
    let t1 = square(&t0);
    /* 2^255 - 21 */
    let ret = mul(&t1, &z11);
    freeze(&ret)
}

#[cfg(test)]
mod tests {}
