use std::ops::{Add, Mul, Neg, Sub};

use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// A scalar value of Curve25519.
#[derive(Copy, Clone, Debug, Default)]
pub struct Scalar([u64; 5]);

impl Scalar {
    /// The value `0`.
    pub const ZERO: Scalar = Scalar([0, 0, 0, 0, 0]);

    /// The value `1`.
    pub const ONE: Scalar = Scalar([1, 0, 0, 0, 0]);

    /// Clamps the given byte array and returns a valid [Scalar].
    #[inline]
    pub fn clamp(x: &[u8; 32]) -> Scalar {
        let mut x = *x;
        x[0] &= 0b1111_1000;
        x[31] &= 0b0111_1111;
        x[31] |= 0b0100_0000;

        Scalar::from_bits(&x)
    }

    /// Reduces the given 256-bit little-endian array modulo `l`.
    pub fn from_bytes(bytes: &[u8; 32]) -> Scalar {
        Scalar::from_bits(bytes).montgomery_mul(&R)
    }

    /// Reduces the given 512-bit little-endian array modulo `l`.
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Scalar {
        let mut words = [0u64; 8];
        for (word, chunk) in words.iter_mut().zip(bytes.chunks(8)) {
            for (j, &b) in chunk.iter().enumerate() {
                *word |= (b as u64) << (j * 8);
            }
        }

        let mask = (1u64 << 52) - 1;

        // (lo * R) / R = lo
        let lo = Scalar([
            words[0] & mask,
            ((words[0] >> 52) | (words[1] << 12)) & mask,
            ((words[1] >> 40) | (words[2] << 24)) & mask,
            ((words[2] >> 28) | (words[3] << 36)) & mask,
            ((words[3] >> 16) | (words[4] << 48)) & mask,
        ])
        .montgomery_mul(&R);

        // (hi * R^2) / R = hi * R
        let hi = Scalar([
            (words[4] >> 4) & mask,
            ((words[4] >> 56) | (words[5] << 8)) & mask,
            ((words[5] >> 44) | (words[6] << 20)) & mask,
            ((words[6] >> 32) | (words[7] << 32)) & mask,
            words[7] >> 20,
        ])
        .montgomery_mul(&RR);

        &hi + &lo
    }

    fn from_bits(bytes: &[u8; 32]) -> Scalar {
        let mut words = [0u64; 4];
        for (word, chunk) in words.iter_mut().zip(bytes.chunks(8)) {
            for (j, &b) in chunk.iter().enumerate() {
                *word |= (b as u64) << (j * 8);
            }
        }

        let mask = (1u64 << 52) - 1;
        let top_mask = (1u64 << 48) - 1;

        Scalar([
            words[0] & mask,
            ((words[0] >> 52) | (words[1] << 12)) & mask,
            ((words[1] >> 40) | (words[2] << 24)) & mask,
            ((words[2] >> 28) | (words[3] << 36)) & mask,
            (words[3] >> 16) & top_mask,
        ])
    }

    /// Returns the scalar as a byte array.
    pub const fn as_bytes(&self) -> [u8; 32] {
        [
            self.0[0] as u8,
            (self.0[0] >> 8) as u8,
            (self.0[0] >> 16) as u8,
            (self.0[0] >> 24) as u8,
            (self.0[0] >> 32) as u8,
            (self.0[0] >> 40) as u8,
            ((self.0[0] >> 48) | (self.0[1] << 4)) as u8,
            (self.0[1] >> 4) as u8,
            (self.0[1] >> 12) as u8,
            (self.0[1] >> 20) as u8,
            (self.0[1] >> 28) as u8,
            (self.0[1] >> 36) as u8,
            (self.0[1] >> 44) as u8,
            self.0[2] as u8,
            (self.0[2] >> 8) as u8,
            (self.0[2] >> 16) as u8,
            (self.0[2] >> 24) as u8,
            (self.0[2] >> 32) as u8,
            (self.0[2] >> 40) as u8,
            ((self.0[2] >> 48) | (self.0[3] << 4)) as u8,
            (self.0[3] >> 4) as u8,
            (self.0[3] >> 12) as u8,
            (self.0[3] >> 20) as u8,
            (self.0[3] >> 28) as u8,
            (self.0[3] >> 36) as u8,
            (self.0[3] >> 44) as u8,
            self.0[4] as u8,
            (self.0[4] >> 8) as u8,
            (self.0[4] >> 16) as u8,
            (self.0[4] >> 24) as u8,
            (self.0[4] >> 32) as u8,
            (self.0[4] >> 40) as u8,
        ]
    }

    /// Returns `true` if the scalar's LSB is zero.
    #[inline]
    pub(crate) fn is_zero_lsb(&self) -> Choice {
        !Choice::from(self.0[0] as u8 & 1)
    }

    /// If the scalar's LSB is zero, returns `self`. Otherwise, returns `-self`, which has a zero
    /// LSB.
    #[inline]
    pub(crate) fn to_zero_lsb(mut self) -> Scalar {
        let zero_lsb = self.is_zero_lsb();
        Scalar::conditional_negate(&mut self, !zero_lsb);
        debug_assert!(bool::from(self.is_zero_lsb()));
        self
    }

    /// Returns the multiplicative inverse of the scalar.
    pub fn invert(&self) -> Scalar {
        self.montgomerize().montgomery_invert().normalize()
    }

    fn montgomery_invert(&self) -> Scalar {
        // Uses the addition chain from
        // https://briansmith.org/ecc-inversion-addition-chains-01#curve25519_scalar_inversion
        let bits_1 = self;
        let bits_10 = bits_1.montgomery_square();
        let bits_100 = bits_10.montgomery_square();
        let bits_11 = bits_10.montgomery_mul(bits_1);
        let bits_101 = bits_10.montgomery_mul(&bits_11);
        let bits_111 = bits_10.montgomery_mul(&bits_101);
        let bits_1001 = bits_10.montgomery_mul(&bits_111);
        let bits_1011 = bits_10.montgomery_mul(&bits_1001);
        let bits_1111 = bits_100.montgomery_mul(&bits_1011);

        // _10000
        let mut y = bits_1111.montgomery_mul(bits_1);

        #[inline]
        fn square_multiply(y: &mut Scalar, squarings: usize, x: &Scalar) {
            for _ in 0..squarings {
                *y = y.montgomery_square();
            }
            *y = y.montgomery_mul(x);
        }

        square_multiply(&mut y, 123 + 3, &bits_101);
        square_multiply(&mut y, 2 + 2, &bits_11);
        square_multiply(&mut y, 1 + 4, &bits_1111);
        square_multiply(&mut y, 1 + 4, &bits_1111);
        square_multiply(&mut y, 4, &bits_1001);
        square_multiply(&mut y, 2, &bits_11);
        square_multiply(&mut y, 1 + 4, &bits_1111);
        square_multiply(&mut y, 1 + 3, &bits_101);
        square_multiply(&mut y, 3 + 3, &bits_101);
        square_multiply(&mut y, 3, &bits_111);
        square_multiply(&mut y, 1 + 4, &bits_1111);
        square_multiply(&mut y, 2 + 3, &bits_111);
        square_multiply(&mut y, 2 + 2, &bits_11);
        square_multiply(&mut y, 1 + 4, &bits_1011);
        square_multiply(&mut y, 2 + 4, &bits_1011);
        square_multiply(&mut y, 6 + 4, &bits_1001);
        square_multiply(&mut y, 2 + 2, &bits_11);
        square_multiply(&mut y, 3 + 2, &bits_11);
        square_multiply(&mut y, 3 + 2, &bits_11);
        square_multiply(&mut y, 1 + 4, &bits_1001);
        square_multiply(&mut y, 1 + 3, &bits_111);
        square_multiply(&mut y, 2 + 4, &bits_1111);
        square_multiply(&mut y, 1 + 4, &bits_1011);
        square_multiply(&mut y, 3, &bits_101);
        square_multiply(&mut y, 2 + 4, &bits_1111);
        square_multiply(&mut y, 3, &bits_101);
        square_multiply(&mut y, 1 + 2, &bits_11);

        y
    }

    /// Compute `(a^2) / R` (mod l) in Montgomery form, where R is the Montgomery modulus 2^260
    #[inline(never)]
    fn montgomery_square(&self) -> Scalar {
        montgomery_reduce(&self.square_internal())
    }

    /// Compute `a^2`
    #[inline(always)]
    const fn square_internal(&self) -> [u128; 9] {
        let a = self;
        let aa = [a.0[0] * 2, a.0[1] * 2, a.0[2] * 2, a.0[3] * 2];

        [
            m(a.0[0], a.0[0]),
            m(aa[0], a.0[1]),
            m(aa[0], a.0[2]) + m(a.0[1], a.0[1]),
            m(aa[0], a.0[3]) + m(aa[1], a.0[2]),
            m(aa[0], a.0[4]) + m(aa[1], a.0[3]) + m(a.0[2], a.0[2]),
            m(aa[1], a.0[4]) + m(aa[2], a.0[3]),
            m(aa[2], a.0[4]) + m(a.0[3], a.0[3]),
            m(aa[3], a.0[4]),
            m(a.0[4], a.0[4]),
        ]
    }

    /// Compute `a * b`
    #[inline(always)]
    #[rustfmt::skip]
    const fn mul_internal(&self, b: &Scalar) -> [u128; 9] {
        let a = self;
        [
            m(a.0[0], b.0[0]),
            m(a.0[0], b.0[1]) + m(a.0[1], b.0[0]),
            m(a.0[0], b.0[2]) + m(a.0[1], b.0[1]) + m(a.0[2], b.0[0]),
            m(a.0[0], b.0[3]) + m(a.0[1], b.0[2]) + m(a.0[2], b.0[1]) + m(a.0[3], b.0[0]),
            m(a.0[0], b.0[4]) + m(a.0[1], b.0[3]) + m(a.0[2], b.0[2]) + m(a.0[3], b.0[1]) + m(a.0[4], b.0[0]),
            m(a.0[1], b.0[4]) + m(a.0[2], b.0[3]) + m(a.0[3], b.0[2]) + m(a.0[4], b.0[1]),
            m(a.0[2], b.0[4]) + m(a.0[3], b.0[3]) + m(a.0[4], b.0[2]),
            m(a.0[3], b.0[4]) + m(a.0[4], b.0[3]),
            m(a.0[4], b.0[4]),
        ]
    }

    /// Puts a scalar in to Montgomery form, i.e. computes `a*R (mod l)`
    #[inline(never)]
    fn montgomerize(&self) -> Scalar {
        self.montgomery_mul(&RR)
    }

    /// Takes a scalar out of Montgomery form, i.e. computes `a/R (mod l)`
    #[inline(never)]
    fn normalize(&self) -> Scalar {
        let mut limbs = [0u128; 9];
        for (l, s) in limbs.iter_mut().zip(self.0) {
            *l = s as u128;
        }
        montgomery_reduce(&limbs)
    }

    #[inline(always)]
    fn montgomery_mul(&self, b: &Scalar) -> Scalar {
        montgomery_reduce(&self.mul_internal(b))
    }
}

impl Add for &Scalar {
    type Output = Scalar;

    fn add(self, rhs: Self) -> Self::Output {
        let mut sum = Scalar::ZERO;
        let mask = (1u64 << 52) - 1;

        // a + b
        let mut carry: u64 = 0;
        for ((a, b), c) in sum.0.iter_mut().zip(self.0).zip(rhs.0) {
            carry = b + c + (carry >> 52);
            *a = carry & mask;
        }

        // subtract l if the sum is >= l
        &sum - &L
    }
}

impl Sub for &Scalar {
    type Output = Scalar;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut difference = Scalar::ZERO;
        let mask = (1u64 << 52) - 1;

        // a - b
        let mut borrow: u64 = 0;
        for ((a, b), c) in difference.0.iter_mut().zip(self.0).zip(rhs.0) {
            borrow = b.wrapping_sub(c + (borrow >> 63));
            *a = borrow & mask;
        }

        // conditionally add l if the difference is negative
        let underflow_mask = ((borrow >> 63) ^ 1).wrapping_sub(1);
        let mut carry: u64 = 0;
        for (a, b) in difference.0.iter_mut().zip(L.0) {
            carry = (carry >> 52) + *a + (b & underflow_mask);
            *a = carry & mask;
        }

        difference
    }
}

impl Mul for &Scalar {
    type Output = Scalar;

    fn mul(self, rhs: Self) -> Self::Output {
        let ab = montgomery_reduce(&self.mul_internal(rhs));
        montgomery_reduce(&ab.mul_internal(&RR))
    }
}

impl Neg for &Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        &Scalar::ZERO - &montgomery_reduce(&self.mul_internal(&R))
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
            u64::conditional_select(&a.0[4], &b.0[4], choice),
        ])
    }
}

impl Eq for Scalar {}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// u64 * u64 = u128 multiply helper
#[inline(always)]
const fn m(x: u64, y: u64) -> u128 {
    (x as u128) * (y as u128)
}

/// Compute `limbs/R` (mod l), where R is the Montgomery modulus 2^260
#[inline(always)]
fn montgomery_reduce(limbs: &[u128; 9]) -> Scalar {
    #[inline(always)]
    const fn part1(sum: u128) -> (u128, u64) {
        let p = (sum as u64).wrapping_mul(LFACTOR) & ((1u64 << 52) - 1);
        ((sum + m(p, L.0[0])) >> 52, p)
    }

    #[inline(always)]
    const fn part2(sum: u128) -> (u128, u64) {
        let w = (sum as u64) & ((1u64 << 52) - 1);
        (sum >> 52, w)
    }

    // note: l[3] is zero, so its multiples can be skipped
    let l = &L;

    // the first half computes the Montgomery adjustment factor n, and begins adding n*l to make limbs divisible by R
    let (carry, n0) = part1(limbs[0]);
    let (carry, n1) = part1(carry + limbs[1] + m(n0, l.0[1]));
    let (carry, n2) = part1(carry + limbs[2] + m(n0, l.0[2]) + m(n1, l.0[1]));
    let (carry, n3) = part1(carry + limbs[3] + m(n1, l.0[2]) + m(n2, l.0[1]));
    let (carry, n4) = part1(carry + limbs[4] + m(n0, l.0[4]) + m(n2, l.0[2]) + m(n3, l.0[1]));

    // limbs is divisible by R now, so we can divide by R by simply storing the upper half as the result
    let (carry, r0) = part2(carry + limbs[5] + m(n1, l.0[4]) + m(n3, l.0[2]) + m(n4, l.0[1]));
    let (carry, r1) = part2(carry + limbs[6] + m(n2, l.0[4]) + m(n4, l.0[2]));
    let (carry, r2) = part2(carry + limbs[7] + m(n3, l.0[4]));
    let (carry, r3) = part2(carry + limbs[8] + m(n4, l.0[4]));
    let r4 = carry as u64;

    // result may be >= l, so attempt to subtract l
    &Scalar([r0, r1, r2, r3, r4]) - l
}

/// `R` = R % L where R = 2^260
const R: Scalar = Scalar([
    0x000f_48bd_6721_e6ed,
    0x0003_bab5_ac67_e45a,
    0x000f_ffff_eb35_e51b,
    0x000f_ffff_ffff_ffff,
    0x0000_0fff_ffff_ffff,
]);

/// `RR` = (R^2) % L where R = 2^260
const RR: Scalar = Scalar([
    0x0009_d265_e952_d13b,
    0x000d_63c7_15be_a69f,
    0x0005_be65_cb68_7604,
    0x0003_dcee_c73d_217f,
    0x0000_0941_1b7c_309a,
]);

/// `L` * `LFACTOR` = -1 (mod 2^52)
const LFACTOR: u64 = 0x51da312547e1b;

/// `L` is the order of base point, i.e. 2^252 + 27742317777372353535851937790883648493
const L: Scalar = Scalar([
    0x0002_631a_5cf5_d3ed,
    0x000d_ea2f_79cd_6581,
    0x0000_0000_0014_def9,
    0x0000_0000_0000_0000,
    0x0000_1000_0000_0000,
]);

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use super::*;

    #[test]
    fn default_is_zero() {
        assert_eq!(Scalar::ZERO, Scalar::default());
    }

    #[test]
    fn zeroization() {
        let mut d = Scalar::clamp(&thread_rng().gen());

        assert_ne!(d, Scalar::ZERO);

        d.zeroize();

        assert_eq!(d, Scalar::ZERO);
    }
}
