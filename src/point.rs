use std::ops::{Add, Mul, Sub};

use fiat_crypto::curve25519_64::*;
use subtle::ConstantTimeEq;

use crate::Scalar;

/// The generator point for Curve25519.
pub const G: Point = Point([9, 0, 0, 0, 0]);

/// A point on Curve25519. (Technically, only the `x` coordinate of the affine representation.)
#[derive(Copy, Clone, Default)]
pub struct Point(pub(crate) [u64; 5]);

impl Point {
    /// Parses the given byte array as a [Point].
    ///
    /// All possible byte arrays are valid points.
    #[inline]
    pub fn from_bytes(x: &[u8; 32]) -> Point {
        let mut ret = Point::default();
        let mut x = *x;
        x[31] &= 127;
        fiat_25519_from_bytes(&mut ret.0, &x);
        ret.freeze()
    }

    /// Returns the point as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut ret = Default::default();
        fiat_25519_to_bytes(&mut ret, &self.0);
        ret
    }

    /// The identity point of Curve25519.
    pub const ZERO: Point = Point([0, 0, 0, 0, 0]);

    /// The `1` value of Curve25519.
    pub const ONE: Point = Point([1, 0, 0, 0, 0]);

    /// Returns `true` iff the point is equal to zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.as_bytes().ct_eq(&[0u8; 32]).into()
    }

    /// Returns `self * 12166 mod m`.
    #[inline]
    pub fn mul121666(&self) -> Point {
        let mut ret = Point::default();
        fiat_25519_carry_scmul_121666(&mut ret.0, &self.0);
        ret
    }

    /// Returns `self * self`.
    #[inline]
    pub fn square(&self) -> Point {
        let mut ret = Point::default();
        fiat_25519_carry_square(&mut ret.0, &self.0);
        ret
    }

    /// Returns the multiplicative inverse of the point.
    pub fn invert(&self) -> Point {
        /* 2 */
        let z2 = self.square();
        /* 4 */
        let t1 = z2.square();
        /* 8 */
        let t0 = t1.square();
        /* 9 */
        let z9 = &t0 * self;
        /* 11 */
        let z11 = &z9 * &z2;
        /* 22 */
        let t0 = z11.square();
        /* 2^5 - 2^0 = 31 */
        let z2 = &t0 * &z9;

        /* 2^6 - 2^1 */
        let t0 = z2.square();
        /* 2^7 - 2^2 */
        let t1 = t0.square();
        /* 2^8 - 2^3 */
        let t0 = t1.square();
        /* 2^9 - 2^4 */
        let t1 = t0.square();
        /* 2^10 - 2^5 */
        let t0 = t1.square();
        /* 2^10 - 2^0 */
        let z2 = &t0 * &z2;

        /* 2^11 - 2^1 */
        let mut t0 = z2.square();
        /* 2^12 - 2^2 */
        let mut t1 = t0.square();
        /* 2^20 - 2^10 */
        for _ in (2..10).step_by(2) {
            t0 = t1.square();
            t1 = t0.square();
        }
        /* 2^20 - 2^0 */
        let z9 = &t1 * &z2;

        /* 2^21 - 2^1 */
        let mut t0 = z9.square();
        /* 2^22 - 2^2 */
        let mut t1 = t0.square();
        /* 2^40 - 2^20 */
        for _ in (2..20).step_by(2) {
            t0 = t1.square();
            t1 = t0.square();
        }
        /* 2^40 - 2^0 */
        let t0 = &t1 * &z9;

        /* 2^41 - 2^1 */
        let mut t1 = t0.square();
        /* 2^42 - 2^2 */
        let mut t0 = t1.square();
        /* 2^50 - 2^10 */
        for _ in (2..10).step_by(2) {
            t1 = t0.square();
            t0 = t1.square();
        }
        /* 2^50 - 2^0 */
        let z2 = &t0 * &z2;

        /* 2^51 - 2^1 */
        let mut t0 = z2.square();
        /* 2^52 - 2^2 */
        let mut t1 = t0.square();
        /* 2^100 - 2^50 */
        for _ in (2..50).step_by(2) {
            t0 = t1.square();
            t1 = t0.square();
        }
        /* 2^100 - 2^0 */
        let z9 = &t1 * &z2;

        /* 2^101 - 2^1 */
        let mut t1 = z9.square();
        /* 2^102 - 2^2 */
        let mut t0 = t1.square();
        /* 2^200 - 2^100 */
        for _ in (2..100).step_by(2) {
            t1 = t0.square();
            t0 = t1.square();
        }
        /* 2^200 - 2^0 */
        let t1 = &t0 * &z9;

        /* 2^201 - 2^1 */
        let mut t0 = t1.square();
        /* 2^202 - 2^2 */
        let mut t1 = t0.square();
        /* 2^250 - 2^50 */
        for _ in (2..50).step_by(2) {
            t0 = t1.square();
            t1 = t0.square();
        }
        /* 2^250 - 2^0 */
        let t0 = &t1 * &z2;

        /* 2^251 - 2^1 */
        let t1 = t0.square();
        /* 2^252 - 2^2 */
        let t0 = t1.square();
        /* 2^253 - 2^3 */
        let t1 = t0.square();
        /* 2^254 - 2^4 */
        let t0 = t1.square();
        /* 2^255 - 2^5 */
        let t1 = t0.square();
        /* 2^255 - 21 */
        &t1 * &z11
    }

    #[inline]
    fn swap(&mut self, b: &mut Point, swap: u8) {
        // SAFETY: This is a part of fiat input bounds.
        assert!(swap == 1 || swap == 0);

        let tmp_x = *self;
        let tmp_y = *b;

        fiat_25519_selectznz(&mut self.0, swap, &tmp_x.0, &tmp_y.0);
        fiat_25519_selectznz(&mut b.0, swap, &tmp_y.0, &tmp_x.0);
    }

    #[inline]
    fn freeze(&self) -> Point {
        let mut ret = Point::default();
        fiat_25519_carry(&mut ret.0, &self.0);
        ret
    }
}

impl Add for &Point {
    type Output = Point;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let mut ret = Point::default();
        fiat_25519_add(&mut ret.0, &self.0, &rhs.0);
        ret.freeze()
    }
}

impl Sub for &Point {
    type Output = Point;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let mut ret = Point::default();
        fiat_25519_sub(&mut ret.0, &self.0, &rhs.0);
        ret.freeze()
    }
}

impl Mul for &Point {
    type Output = Point;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let mut ret = Point::default();
        fiat_25519_carry_mul(&mut ret.0, &self.0, &rhs.0);
        ret
    }
}

impl Mul<&Scalar> for &Point {
    type Output = Point;

    // Montgomery ladder computing q*d via repeated differential additions and constant-time
    // conditional swaps.
    fn mul(self, rhs: &Scalar) -> Self::Output {
        let mut x2 = Point::ONE;
        let mut x3 = *self;
        let mut z3 = Point::ONE;
        let mut z2 = Point::ZERO;
        let mut tmp0: Point;
        let mut tmp1: Point;
        let mut swap_bit: u8 = 0;

        for idx in (0..=254).rev() {
            let bit = ((rhs.0[idx >> 3] >> (idx & 7)) & 1) as u8;
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
            z3 = self * &z2;
            z2 = &tmp1 * &tmp0;
        }

        x2.swap(&mut x3, swap_bit);
        z2.swap(&mut z3, swap_bit);

        z2 = z2.invert();
        &x2 * &z2
    }
}

#[cfg(test)]
mod tests {}
