use fiat_crypto::curve25519_64::*;
use std::ops::{Add, Mul, Sub};
use subtle::ConstantTimeEq;

#[derive(Copy, Clone, Default)]
pub struct Fe25519(pub(crate) [u64; 5]);

impl Fe25519 {
    #[inline]
    pub fn swap(&mut self, b: &mut Fe25519, swap: u8) {
        // SAFETY: This is a part of fiat input bounds.
        assert!(swap == 1 || swap == 0);

        let tmp_x = *self;
        let tmp_y = *b;

        fiat_25519_selectznz(&mut self.0, swap, &tmp_x.0, &tmp_y.0);
        fiat_25519_selectznz(&mut b.0, swap, &tmp_y.0, &tmp_x.0);
    }

    #[inline]
    pub fn freeze(&self) -> Fe25519 {
        let mut ret = Fe25519::default();
        fiat_25519_carry(&mut ret.0, &self.0);
        ret
    }

    #[inline]
    pub fn from_bytes(x: &[u8; 32]) -> Fe25519 {
        let mut ret = Fe25519::default();
        let mut x = *x;
        x[31] &= 127;
        fiat_25519_from_bytes(&mut ret.0, &x);
        ret.freeze()
    }

    #[inline]
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut ret = Default::default();
        fiat_25519_to_bytes(&mut ret, &self.0);
        ret
    }

    pub const fn one() -> Fe25519 {
        Fe25519([1, 0, 0, 0, 0])
    }

    pub const fn zero() -> Fe25519 {
        Fe25519([0, 0, 0, 0, 0])
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.as_bytes().ct_eq(&[0u8; 32]).into()
    }

    #[inline]
    pub fn mul121666(&self) -> Fe25519 {
        let mut ret = Fe25519::default();
        fiat_25519_carry_scmul_121666(&mut ret.0, &self.0);
        ret.freeze()
    }

    #[inline]
    pub fn square(&self) -> Fe25519 {
        let mut ret = Fe25519::default();
        fiat_25519_carry_square(&mut ret.0, &self.0);
        ret.freeze()
    }

    pub fn invert(&self) -> Fe25519 {
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
        let ret = &t1 * &z11;
        ret.freeze()
    }
}

impl Add for &Fe25519 {
    type Output = Fe25519;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let mut ret = Fe25519::default();
        fiat_25519_add(&mut ret.0, &self.0, &rhs.0);
        ret.freeze()
    }
}

impl Sub for &Fe25519 {
    type Output = Fe25519;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let mut ret = Fe25519::default();
        fiat_25519_sub(&mut ret.0, &self.0, &rhs.0);
        ret.freeze()
    }
}

impl Mul for &Fe25519 {
    type Output = Fe25519;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let mut ret = Fe25519::default();
        fiat_25519_carry_mul(&mut ret.0, &self.0, &rhs.0);
        ret.freeze()
    }
}

#[cfg(test)]
mod tests {}
