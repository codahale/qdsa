use std::ops::{Add, Mul, Neg, Sub};

use fiat_crypto::curve25519_64::*;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::scalar::Scalar;

/// The generator point for Curve25519.
pub const G: Point = Point([9, 0, 0, 0, 0]);

/// A point on Curve25519.
///
/// Technically, only the `u` coordinate of Curve25519's Montgomery form.
#[derive(Copy, Clone, Debug, Default)]
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
        // Zero the top two bits.
        let mut rep = *rep;
        rep[31] &= 0b0011_1111;

        let r = Point::from_bytes(&rep).square();
        let t1 = &r + &r;
        let t2 = (&t1 + &Point::ONE).square();
        let t3 = &(&(&A2 * &t1) - &t2) * &A;
        let (t1, is_square) = (&t3 * &(&t2 * &(&t1 + &Point::ONE))).inv_sqrt();
        let u = Point::conditional_select(&(&r * &U_FACTOR), &Point::ONE, is_square);
        -&(&(&(&(&u * &A) * &t3) * &t2) * &t1.square())
    }

    /// Returns the Elligator2 representative, if any, using a random `mask` value to obscure
    /// otherwise constant bits.
    pub fn to_elligator(&self, mask: u8) -> Option<[u8; 32]> {
        let t1 = self; // u
        let t2 = t1 + &A; // u + A
        let (t3, is_square) = (&(t1 * &t2) * &MINUS_TWO).inv_sqrt(); // sqrt(-1 / non_square * u * (u+A))

        // The only variable time bit. This ultimately reveals how many tries it took us to find
        // a representable key. This does not affect security as long as we try keys at random.
        if is_square.into() {
            // multiply by u if v is positive, multiply by u+A otherwise
            let t3 = &Point::conditional_select(t1, &t2, (mask & 1).into()) * &t3;
            let t3 = Point::conditional_select(&t3, &-&t3, (&t3 * &TWO).is_odd());

            let mut rep = t3.as_bytes();
            rep[31] |= mask & 0b1100_0000; // use the top two bits of the mask
            Some(rep)
        } else {
            None
        }
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

    /// Parses the given slice as a [Point].
    ///
    /// Only properly encoded points are parsed.
    #[inline]
    pub fn from_canonical_bytes(x: &[u8]) -> Option<Point> {
        let x: [u8; 32] = x.try_into().ok()?;
        (x[31] & 0b1000_0000 == 0).then(|| Point::from_bytes(&x))
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
    #[inline]
    pub fn invert(&self) -> Point {
        // The bits of p-2 = 2^255 -19 -2 are 11010111111...11.
        //
        //                                 nonzero bits of exponent
        let (t19, t3) = self.pow22501(); // t19: 249..0 ; t3: 3,1,0
        let t20 = t19.pow2k(5); // 254..5
        &t20 * &t3 // 254..5,3,1,0
    }

    // Inverse square root.
    // Returns true if x is a square, false otherwise.
    // After the call:
    //   isr = sqrt(1/x)        if x is a non-zero square.
    //   isr = sqrt(sqrt(-1)/x) if x is not a square.
    //   isr = 0                if x is zero.
    // We do not guarantee the sign of the square root.
    fn inv_sqrt(&self) -> (Point, Choice) {
        let t0 = self.square();
        let t1 = t0.square();
        let t1 = &t1.square() * self;
        let t0 = &(&t1 * &t0).square() * &t1;
        let t0 = &(1..5).fold(t0.square(), |t1, _| t1.square()) * &t0;
        let t1 = &(1..10).fold(t0.square(), |t1, _| t1.square()) * &t0;
        let t1 = &(1..20).fold(t1.square(), |t2, _| t2.square()) * &t1;
        let t0 = &(1..10).fold(t1.square(), |t1, _| t1.square()) * &t0;
        let t1 = &(1..50).fold(t0.square(), |t1, _| t1.square()) * &t0;
        let t1 = &(1..100).fold(t1.square(), |t2, _| t2.square()) * &t1;
        let t0 = &(1..50).fold(t1.square(), |t1, _| t1.square()) * &t0;
        let t0 = &(1..2).fold(t0.square(), |t0, _| t0.square()) * self;

        // quartic = x^((p-1)/4)
        let quartic = &t0.square() * self;
        let z0 = self.ct_eq(&Point::ZERO);
        let p1 = quartic.ct_eq(&Point::ONE);
        let m1 = quartic.ct_eq(&Point::MINUS_ONE);
        let ms = quartic.ct_eq(&MINUS_SQRT_M1);

        // if quartic == -1 or sqrt(-1)
        // then  isr = x^((p-1)/4) * sqrt(-1)
        // else  isr = x^((p-1)/4)
        (
            Point::conditional_select(&(&t0 * &SQRT_M1), &t0, !(m1 | ms)),
            p1 | m1 | z0,
        )
    }

    #[inline]
    fn is_odd(&self) -> Choice {
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
        let mut output = Point::default();
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

const MINUS_SQRT_M1: Point = Point([
    0x0001_e4d8_b5f1_5f3d,
    0x0007_2a5a_0370_e762,
    0x0000_10a1_6342_f39f,
    0x0000_7a6a_597f_b361,
    0x0005_47cd_b7fb_03e2,
]);

const TWO: Point = Point([
    0x0000_0000_0000_0002,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
]);

const MINUS_TWO: Point = Point([
    0x0007_ffff_ffff_ffeb,
    0x0007_ffff_ffff_ffff,
    0x0007_ffff_ffff_ffff,
    0x0007_ffff_ffff_ffff,
    0x0007_ffff_ffff_ffff,
]);

const A: Point = Point([
    0x0000_0000_0007_6d06,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
]);

const A2: Point = Point([
    0x0000_0037_24c2_1c24,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
]);

const U_FACTOR: Point = Point([
    0x0003_c9b1_6be2_be8d,
    0x0006_54b4_06e1_cec4,
    0x0000_2142_c685_e73f,
    0x0000_f4d4_b2ff_66c2,
    0x0002_8f9b_6ff6_07c4,
]);

#[cfg(test)]
mod tests {
    use hex_literal::hex;
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
    fn from_elligator_kat() {
        // generated with Monocypher 3.1.3
        // https://github.com/LoupVaillant/Monocypher/releases/tag/3.1.3

        let q = Point::from_bytes(&hex!(
            "afe7c5982a22425108e129bc9e3c0b1260054e511fad5aa1196a207489654f61"
        ));

        assert_eq!(
            Point::from_elligator(&hex!(
                "08a9742639fef01c831c72965f01eac13daed3097d9e418108079d366346ba27"
            )),
            q
        );
        assert_eq!(
            Point::from_elligator(&hex!(
                "68ca80ac9f3ae0269fe77facd109a0dcf35e71ab5baf374fd96381ef7938d520"
            )),
            q
        );
        assert_eq!(
            Point::from_elligator(&hex!(
                "68ca80ac9f3ae0269fe77facd109a0dcf35e71ab5baf374fd96381ef7938d560"
            )),
            q
        );
        assert_eq!(
            Point::from_elligator(&hex!(
                "68ca80ac9f3ae0269fe77facd109a0dcf35e71ab5baf374fd96381ef7938d5e0"
            )),
            q
        );
    }

    #[test]
    fn to_elligator_kat() {
        // generated with Monocypher 3.1.3
        // https://github.com/LoupVaillant/Monocypher/releases/tag/3.1.3

        let q = Point::from_bytes(&hex!(
            "afe7c5982a22425108e129bc9e3c0b1260054e511fad5aa1196a207489654f61"
        ));

        assert_eq!(
            q.to_elligator(0b0000_0000),
            Some(hex!(
                "08a9742639fef01c831c72965f01eac13daed3097d9e418108079d366346ba27"
            ))
        );

        assert_eq!(
            q.to_elligator(0b0000_0001),
            Some(hex!(
                "68ca80ac9f3ae0269fe77facd109a0dcf35e71ab5baf374fd96381ef7938d520"
            ))
        );

        assert_eq!(
            q.to_elligator(0b0100_0001),
            Some(hex!(
                "68ca80ac9f3ae0269fe77facd109a0dcf35e71ab5baf374fd96381ef7938d560"
            ))
        );

        assert_eq!(
            q.to_elligator(0b1100_0001),
            Some(hex!(
                "68ca80ac9f3ae0269fe77facd109a0dcf35e71ab5baf374fd96381ef7938d5e0"
            ))
        );
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

    #[test]
    fn zeroization() {
        let mut q = Point::from_elligator(&thread_rng().gen());

        assert_ne!(q, Point::ZERO);

        q.zeroize();

        assert_eq!(q, Point::ZERO);
    }
}
