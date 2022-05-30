use std::fmt::{Debug, Formatter};
use std::ops::{Add, Mul, Neg, Sub};

use fiat_crypto::curve25519_64::*;
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};
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
        0x0007_ffff_ffff_ffec,
        0x0007_ffff_ffff_ffff,
        0x0007_ffff_ffff_ffff,
        0x0007_ffff_ffff_ffff,
        0x0007_ffff_ffff_ffff,
    ]);

    /// Decodes the given Elligator2 representative and returns a [Point].
    pub fn from_elligator(rep: &[u8; 32]) -> Point {
        // Set the top and bottom bits back to zero.
        let mut rep = *rep;
        rep[31] &= 0b0111_1111;
        rep[0] &= 0b1111_1110;

        let r_0 = Point::from_bytes(&rep);
        let one = Point::ONE;
        let d_1 = &one + &r_0.square2(); /* 2r^2 */

        let d = &MONTGOMERY_A_NEG * &(d_1.invert()); /* A/(1+2r^2) */

        let d_sq = &d.square();
        let au = &MONTGOMERY_A * &d;

        let inner = &(d_sq + &au) + &one;
        let eps = &d * &inner; /* eps = d^3 + Ad^2 + d */

        let (eps_is_sq, _eps) = Point::sqrt_ratio_i(&eps, &one);

        let tmp = Point::conditional_select(&MONTGOMERY_A, &Point::ZERO, eps_is_sq); /* 0, or A if nonsquare*/
        let u = &d + &tmp; /* d, or d+A if nonsquare */
        Point::conditional_select(&u, &-&u, !eps_is_sq) /* d, or -d-A if nonsquare */
    }

    /// Parses the given byte array as a [Point].
    ///
    /// All possible byte arrays are valid points.
    #[inline]
    pub fn from_bytes(x: &[u8; 32]) -> Point {
        let mut x = *x;
        x[31] &= 0b0111_1111;

        let mut ret = Point::default();
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

    /// Returns the Elligator2 representative, if any, using a random mask value to obscure sign
    /// bits.
    pub fn to_elligator(&self, mask: u8) -> Option<[u8; 32]> {
        let one = Point::ONE;
        let u_plus_a = self + &MONTGOMERY_A;
        let uu_plus_u_a = self * &u_plus_a;

        // Condition: u is on the curve
        let vv = &(self * &uu_plus_u_a) + self;
        let (u_is_on_curve, _) = Point::sqrt_ratio_i(&vv, &one);
        if (!u_is_on_curve).into() {
            return None;
        }

        // Condition: u != -A
        if self == &MONTGOMERY_A_NEG {
            return None;
        }

        // Condition: -2u(u+A) is a square
        let uu2_plus_u_a2 = &uu_plus_u_a + &uu_plus_u_a;
        // We compute root = sqrt(-1/2u(u+A)) to speed up the calculation.
        // This is a square if and only if -2u(u+A) is.
        let (is_square, root) = Point::sqrt_ratio_i(&Point::MINUS_ONE, &uu2_plus_u_a2);
        if (!(is_square | root.is_zero())).into() {
            return None;
        }

        // Use the top bit of the mask to pick the sign of v.
        let v_is_negative = Choice::from(mask >> 7);

        // if !v_is_negative: r = sqrt(-u / 2(u + a)) = root * u
        // if  v_is_negative: r = sqrt(-(u+A) / 2u)   = root * (u + A)
        let mut r = &root * &Point::conditional_select(self, &u_plus_a, v_is_negative);

        // Both r and -r are valid results. Pick the nonnegative one.
        r.conditional_negate(r.is_negative());

        // As such, the representative will always have a constant low bit of zero and a constant
        // high bit of zero. Use the bottom bit of the mask to obscure the constant top bit of the
        // representative and the second-to-bottom bit of the mask to obscure the constant bottom
        // bit of the representative. If the mask is randomly generated, this should produce a fully
        // uniform representative.
        let mut rep = r.as_bytes();
        rep[31] ^= mask << 7;
        rep[0] ^= (mask & 0b000_0010) >> 1;

        Some(rep)
    }

    fn square2(&self) -> Point {
        let mut square = self.pow2k(1);
        for v in square.0.iter_mut() {
            *v *= 2;
        }
        square
    }

    fn sqrt_ratio_i(u: &Point, v: &Point) -> (Choice, Point) {
        let v3 = &v.square() * v;
        let v7 = &v3.square() * v;
        let r = &(u * &v3) * &(u * &v7).pow_p58();
        let check = v * &r.square();

        let correct_sign_sqrt = check.ct_eq(u);
        let neg_u = -u;
        let flipped_sign_sqrt = check.ct_eq(&neg_u);
        let flipped_sign_sqrt_i = check.ct_eq(&(&neg_u * &SQRT_M1));

        let r = Point::conditional_select(
            &r,
            &(&r * &SQRT_M1),
            flipped_sign_sqrt | flipped_sign_sqrt_i,
        );

        // Choose the nonnegative square root.
        let r = Point::conditional_select(&r, &-&r, r.is_negative());

        let was_nonzero_square = correct_sign_sqrt | flipped_sign_sqrt;

        (was_nonzero_square, r)
    }

    #[inline]
    fn is_negative(&self) -> Choice {
        let mut b = [0u8; 32];
        fiat_25519_to_bytes(&mut b, &self.0);
        (b[0] & 1).into()
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
        let rhs = rhs.as_bytes();

        let mut x2 = Point::ONE;
        let mut x3 = *self;
        let mut z3 = Point::ONE;
        let mut z2 = Point::ZERO;
        let mut swap = Choice::from(0);

        for idx in (0..=254).rev() {
            let bit = (((rhs[idx >> 3] >> (idx & 7)) & 1) as u8).into();
            swap ^= bit;
            Point::conditional_swap(&mut x2, &mut x3, swap);
            Point::conditional_swap(&mut z2, &mut z3, swap);
            swap = bit;

            let tmp0 = &x3 - &z3;
            let tmp1 = &x2 - &z2;
            x2 = &x2 + &z2;
            z2 = &x3 + &z3;
            z3 = &tmp0 * &x2;
            z2 = &z2 * &tmp1;
            let tmp0 = tmp1.square();
            let tmp1 = x2.square();
            x3 = &z3 + &z2;
            z2 = &z3 - &z2;
            x2 = &tmp1 * &tmp0;
            let tmp1 = &tmp1 - &tmp0;
            z2 = z2.square();
            z3 = tmp1.mul121666();
            x3 = x3.square();
            let tmp0 = &tmp0 + &z3;
            z3 = self * &z2;
            z2 = &tmp1 * &tmp0;
        }

        Point::conditional_swap(&mut x2, &mut x3, swap);
        Point::conditional_swap(&mut z2, &mut z3, swap);

        &x2 * &z2.invert()
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
        self.0.fmt(f)
    }
}

impl Zeroize for Point {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ConditionallySelectable for Point {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut ret = *a;
        fiat_25519_selectznz(&mut ret.0, choice.unwrap_u8(), &a.0, &b.0);
        ret
    }
}

const SQRT_M1: Point = Point([
    0x0006_1b27_4a0e_a0b0,
    0x0000_d5a5_fc8f_189d,
    0x0007_ef5e_9cbd_0c60,
    0x0007_8595_a680_4c9e,
    0x0002_b832_4804_fc1d,
]);

const MONTGOMERY_A: Point = Point([486662, 0, 0, 0, 0]);

const MONTGOMERY_A_NEG: Point = Point([
    0x0007_ffff_fff8_92e7,
    0x0007_ffff_ffff_ffff,
    0x0007_ffff_ffff_ffff,
    0x0007_ffff_ffff_ffff,
    0x0007_ffff_ffff_ffff,
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
            if let Some(rep) = q.to_elligator(thread_rng().gen()) {
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
