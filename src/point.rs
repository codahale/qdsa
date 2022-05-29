use std::fmt::{Debug, Formatter};
use std::ops::{Add, Mul, Neg, Sub};

use fiat_crypto::curve25519_64::*;
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::scalar::Scalar;

/// The generator point for Curve25519.
pub const G: Point = Point([9, 0, 0, 0, 0]);

/// A point on Curve25519. (Technically, only the `x` coordinate of the affine representation.)
#[derive(Copy, Clone, Default)]
pub struct Point(pub(crate) [u64; 5]);

impl Point {
    /// The length of an encoded point.
    pub const LEN: usize = 32;

    /// The identity point of Curve25519.
    pub const ZERO: Point = Point([0, 0, 0, 0, 0]);

    /// The `1` value of Curve25519.
    pub const ONE: Point = Point([1, 0, 0, 0, 0]);

    /// The `-1` value of Curve25519.
    pub const MINUS_ONE: Point = Point([
        2251799813685228,
        2251799813685247,
        2251799813685247,
        2251799813685247,
        2251799813685247,
    ]);

    /// Decodes the given Elligator2 representative and returns a [Point].
    pub fn from_elligator(rep: &[u8; 32]) -> Point {
        // Unmask sign bit.
        let mut rep = *rep;
        rep[31] &= 0b01111111;

        let r_0 = Point::from_bytes(&rep);
        let one = Point::ONE;
        let d_1 = &one + &r_0.square2(); /* 2r^2 */

        let d = &MONTGOMERY_A_NEG * &(d_1.invert()); /* A/(1+2r^2) */

        let d_sq = &d.square();
        let au = &MONTGOMERY_A * &d;

        let inner = &(d_sq + &au) + &one;
        let eps = &d * &inner; /* eps = d^3 + Ad^2 + d */

        let (eps_is_sq, _eps) = Point::sqrt_ratio_i(&eps, &one);

        let zero = Point::ZERO;
        let tmp = MONTGOMERY_A.select(&zero, eps_is_sq); /* 0, or A if nonsquare*/
        let u = &d + &tmp; /* d, or d+A if nonsquare */
        u.select(&-&u, !eps_is_sq) /* d, or -d-A if nonsquare */
    }

    /// Parses the given byte array as a [Point].
    ///
    /// All possible byte arrays are valid points.
    #[inline]
    pub fn from_bytes(x: &[u8; 32]) -> Point {
        let mut ret = Point::default();
        let mut x = *x;
        x[31] &= 127;
        fiat_25519_from_bytes(&mut ret.0, &x);
        ret.reduce()
    }

    /// Parses the given byte array as a [Point].
    ///
    /// Only properly encoded points are parsed.
    pub fn from_canonical_bytes(x: &[u8]) -> Option<Point> {
        let x: [u8; 32] = x.try_into().ok()?;
        (x[31] & 128 == 0).then(|| Point::from_bytes(&x))
    }

    /// Returns the point as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut ret = Default::default();
        fiat_25519_to_bytes(&mut ret, &self.0);
        ret
    }

    /// Returns `true` iff the point is equal to zero.
    #[inline]
    pub fn is_zero(&self) -> Choice {
        self.as_bytes().ct_eq(&[0u8; 32])
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
        // The bits of p-2 = 2^255 -19 -2 are 11010111111...11.
        //
        //                                 nonzero bits of exponent
        let (t19, t3) = self.pow22501(); // t19: 249..0 ; t3: 3,1,0
        let t20 = t19.pow2k(5); // 254..5
        &t20 * &t3 // 254..5,3,1,0
    }

    /// Returns the Elligator2 representative, if any.
    pub fn to_elligator(&self, mut rng: impl RngCore + CryptoRng) -> Option<[u8; 32]> {
        // Generate a random byte.
        let mut mask = [0u8; 1];
        rng.fill_bytes(&mut mask);

        // Use the top bit to pick the sign of v.
        let v_is_negative = (mask[0] >> 7).into();

        let one = Point::ONE;
        let u = Point::from_bytes(&self.as_bytes());
        let u_plus_a = &u + &MONTGOMERY_A;
        let uu_plus_u_a = &u * &u_plus_a;

        // Condition: u is on the curve
        let vv = &(&u * &uu_plus_u_a) + &u;
        let (u_is_on_curve, _v) = Point::sqrt_ratio_i(&vv, &one);
        if !bool::from(u_is_on_curve) {
            return None;
        }

        // Condition: u != -A
        if u == MONTGOMERY_A_NEG {
            return None;
        }

        // Condition: -2u(u+A) is a square
        let uu2_plus_u_a2 = &uu_plus_u_a + &uu_plus_u_a;
        // We compute root = sqrt(-1/2u(u+A)) to speed up the calculation.
        // This is a square if and only if -2u(u+A) is.
        let (is_square, root) = Point::sqrt_ratio_i(&Point::MINUS_ONE, &uu2_plus_u_a2);
        if !bool::from(is_square | root.is_zero()) {
            return None;
        }

        // if !v_is_negative: r = sqrt(-u / 2(u + a)) = root * u
        // if  v_is_negative: r = sqrt(-(u+A) / 2u)   = root * (u + A)
        let add = u.select(&u_plus_a, v_is_negative);
        let r = &root * &add;

        // Both r and -r are valid results. Pick the nonnegative one.
        let mut rep = r.select(&-&r, r.is_negative()).as_bytes();

        // Use the bottom bit of the mask byte to obscure the sign bit of the representative.
        rep[31] ^= mask[0] << 7;

        Some(rep)
    }

    fn square2(&self) -> Point {
        let mut square = self.pow2k(1);
        for i in 0..5 {
            square.0[i] *= 2;
        }
        square
    }

    fn sqrt_ratio_i(u: &Point, v: &Point) -> (Choice, Point) {
        let v3 = &v.square() * v;
        let v7 = &v3.square() * v;
        let r = &(u * &v3) * &(u * &v7).pow_p58();
        let check = v * &r.square();

        let i = &SQRT_M1;

        let correct_sign_sqrt = check.ct_eq(u);
        let flipped_sign_sqrt = check.ct_eq(&(-u));
        let flipped_sign_sqrt_i = check.ct_eq(&(&(-u) * i));

        let r = r.select(&(&SQRT_M1 * &r), flipped_sign_sqrt | flipped_sign_sqrt_i);

        // Choose the nonnegative square root.
        let r = r.select(&-&r, r.is_negative());

        let was_nonzero_square = correct_sign_sqrt | flipped_sign_sqrt;

        (was_nonzero_square, r)
    }

    #[inline]
    fn is_negative(&self) -> Choice {
        // inline the required parts of fiat_25519_to_bytes to determine if the LSB is zero
        let mut x1: u64 = 0;
        let mut x2: fiat_25519_u1 = 0;
        fiat_25519_subborrowx_u51(&mut x1, &mut x2, 0x0, self.0[0], 0x7ffffffffffed);
        let mut x3: u64 = 0;
        let mut x4: fiat_25519_u1 = 0;
        fiat_25519_subborrowx_u51(&mut x3, &mut x4, x2, self.0[1], 0x7ffffffffffff);
        let mut x5: u64 = 0;
        let mut x6: fiat_25519_u1 = 0;
        fiat_25519_subborrowx_u51(&mut x5, &mut x6, x4, self.0[2], 0x7ffffffffffff);
        let mut x7: u64 = 0;
        let mut x8: fiat_25519_u1 = 0;
        fiat_25519_subborrowx_u51(&mut x7, &mut x8, x6, self.0[3], 0x7ffffffffffff);
        let mut x9: u64 = 0;
        let mut x10: fiat_25519_u1 = 0;
        fiat_25519_subborrowx_u51(&mut x9, &mut x10, x8, self.0[4], 0x7ffffffffffff);
        let mut x11: u64 = 0;
        fiat_25519_cmovznz_u64(&mut x11, x10, 0x0, 0xffffffffffffffff);
        let mut x12: u64 = 0;
        let mut x13: fiat_25519_u1 = 0;
        fiat_25519_addcarryx_u51(&mut x12, &mut x13, 0x0, x1, x11 & 0x7ffffffffffed);
        (((x12 & 0xff) as u8) & 1).into()
    }

    #[inline]
    fn pow2k(&self, k: u32) -> Point {
        debug_assert!(k > 0);
        let mut output = *self;
        for _ in 0..k {
            let input = output.0;
            fiat_25519_carry_square(&mut output.0, &input);
        }
        output
    }

    #[inline]
    fn pow22501(&self) -> (Point, Point) {
        let t0 = self.square(); // 1         e_0 = 2^1
        let t1 = t0.square().square(); // 3         e_1 = 2^3
        let t2 = self * &t1; // 3,0       e_2 = 2^3 + 2^0
        let t3 = &t0 * &t2; // 3,1,0
        let t4 = t3.square(); // 4,2,1
        let t5 = &t2 * &t4; // 4,3,2,1,0
        let t6 = t5.pow2k(5); // 9,8,7,6,5
        let t7 = &t6 * &t5; // 9,8,7,6,5,4,3,2,1,0
        let t8 = t7.pow2k(10); // 19..10
        let t9 = &t8 * &t7; // 19..0
        let t10 = t9.pow2k(20); // 39..20
        let t11 = &t10 * &t9; // 39..0
        let t12 = t11.pow2k(10); // 49..10
        let t13 = &t12 * &t7; // 49..0
        let t14 = t13.pow2k(50); // 99..50
        let t15 = &t14 * &t13; // 99..0
        let t16 = t15.pow2k(100); // 199..100
        let t17 = &t16 * &t15; // 199..0
        let t18 = t17.pow2k(50); // 249..50
        let t19 = &t18 * &t13; // 249..0

        (t19, t3)
    }

    /// Raise this field element to the power (p-5)/8 = 2^252 -3.
    #[inline]
    fn pow_p58(&self) -> Point {
        // The bits of (p-5)/8 are 101111.....11.
        //
        //                                 nonzero bits of exponent
        let (t19, _) = self.pow22501(); // 249..0
        let t20 = t19.pow2k(2); // 251..2
        self * &t20 // 251..2,0
    }

    #[inline]
    fn select(&self, b: &Point, swap: Choice) -> Point {
        let swap = swap.unwrap_u8();
        let mut ret = *self;
        fiat_25519_selectznz(&mut ret.0, swap, &self.0, &b.0);
        ret
    }

    #[inline]
    pub(crate) fn swap(&mut self, b: &mut Point, swap: Choice) {
        let swap = swap.unwrap_u8();
        let tmp_x = *self;
        let tmp_y = *b;

        fiat_25519_selectznz(&mut self.0, swap, &tmp_x.0, &tmp_y.0);
        fiat_25519_selectznz(&mut b.0, swap, &tmp_y.0, &tmp_x.0);
    }

    #[inline]
    fn reduce(&self) -> Point {
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
        ret.reduce()
    }
}

impl Neg for &Point {
    type Output = Point;

    fn neg(self) -> Self::Output {
        let mut output = *self;
        fiat_25519_opp(&mut output.0, &self.0);
        output.reduce()
    }
}

impl Sub for &Point {
    type Output = Point;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let mut ret = Point::default();
        fiat_25519_sub(&mut ret.0, &self.0, &rhs.0);
        ret.reduce()
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
        let mut swap = Choice::from(0);
        let rhs = rhs.as_bytes();

        for idx in (0..=254).rev() {
            let bit = (((rhs[idx >> 3] >> (idx & 7)) & 1) as u8).into();
            swap ^= bit;
            x2.swap(&mut x3, swap);
            z2.swap(&mut z3, swap);
            swap = bit;

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

        x2.swap(&mut x3, swap);
        z2.swap(&mut z3, swap);

        z2 = z2.invert();
        &x2 * &z2
    }
}

impl Eq for Point {}

impl PartialEq for Point {
    fn eq(&self, other: &Point) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl ConstantTimeEq for Point {
    fn ct_eq(&self, other: &Point) -> Choice {
        self.as_bytes().ct_eq(&other.as_bytes())
    }
}

impl Debug for Point {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x?}", self.as_bytes())
    }
}

impl Zeroize for Point {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

const SQRT_M1: Point = Point([
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
]);

const MONTGOMERY_A: Point = Point([486662, 0, 0, 0, 0]);

const MONTGOMERY_A_NEG: Point = Point([
    2251799813198567,
    2251799813685247,
    2251799813685247,
    2251799813685247,
    2251799813685247,
]);

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use super::*;

    #[test]
    fn elligator_round_trip() {
        let mut hits = 0;
        for _ in 0..100 {
            let d = Scalar::from_bytes(&thread_rng().gen());
            let q = &G * &d;
            if let Some(rep) = q.to_elligator(thread_rng()) {
                let q_p = Point::from_elligator(&rep);
                assert_eq!(q, q_p);
            }
            hits += 1;
        }
        assert!(hits > 1);
    }

    #[test]
    fn canonical_encoding_round_trip() {
        // Always decode properly-encoded points.
        for _ in 0..1_000 {
            let q = Point::from_elligator(&thread_rng().gen());
            let b = q.as_bytes();
            assert!(Point::from_canonical_bytes(&b).is_some())
        }

        // Bounce all points with a high bit set. That's it.
        let q = Point::from_elligator(&thread_rng().gen());
        let mut b = q.as_bytes();
        b[31] |= 128;
        assert!(Point::from_canonical_bytes(&b).is_none());
    }
}
