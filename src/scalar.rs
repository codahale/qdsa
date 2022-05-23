use std::ops::{Add, Mul, Neg, Sub};

use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// A scalar value of Curve25519.
#[derive(Copy, Clone, Default)]
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
        x[0] &= 248;
        x[31] &= 127;
        x[31] |= 64;

        Scalar::from_bits(&x)
    }

    /// Reduces the given 256-bit little-endian array modulo `l`.
    pub fn from_bytes(bytes: &[u8; 32]) -> Scalar {
        Scalar::from_bits(bytes).reduce()
    }

    /// Reduces the given 512-bit little-endian array modulo `l`.
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Scalar {
        let mut words = [0u64; 8];
        for i in 0..8 {
            for j in 0..8 {
                words[i] |= (bytes[(i * 8) + j] as u64) << (j * 8);
            }
        }

        let mask = (1u64 << 52) - 1;
        let mut lo = Scalar::ZERO;
        let mut hi = Scalar::ZERO;

        lo.0[0] = words[0] & mask;
        lo.0[1] = ((words[0] >> 52) | (words[1] << 12)) & mask;
        lo.0[2] = ((words[1] >> 40) | (words[2] << 24)) & mask;
        lo.0[3] = ((words[2] >> 28) | (words[3] << 36)) & mask;
        lo.0[4] = ((words[3] >> 16) | (words[4] << 48)) & mask;
        hi.0[0] = (words[4] >> 4) & mask;
        hi.0[1] = ((words[4] >> 56) | (words[5] << 8)) & mask;
        hi.0[2] = ((words[5] >> 44) | (words[6] << 20)) & mask;
        hi.0[3] = ((words[6] >> 32) | (words[7] << 32)) & mask;
        hi.0[4] = words[7] >> 20;

        lo = montgomery_mul(&lo, &R); // (lo * R) / R = lo
        hi = montgomery_mul(&hi, &RR); // (hi * R^2) / R = hi * R

        &hi + &lo
    }

    fn from_bits(bytes: &[u8; 32]) -> Scalar {
        let mut words = [0u64; 4];
        for i in 0..4 {
            for j in 0..8 {
                words[i] |= (bytes[(i * 8) + j] as u64) << (j * 8);
            }
        }

        let mask = (1u64 << 52) - 1;
        let top_mask = (1u64 << 48) - 1;
        let mut s = Scalar::ZERO;

        s.0[0] = words[0] & mask;
        s.0[1] = ((words[0] >> 52) | (words[1] << 12)) & mask;
        s.0[2] = ((words[1] >> 40) | (words[2] << 24)) & mask;
        s.0[3] = ((words[2] >> 28) | (words[3] << 36)) & mask;
        s.0[4] = (words[3] >> 16) & top_mask;

        s
    }

    /// Returns the scalar as a byte array.
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut s = [0u8; 32];

        s[0] = self.0[0] as u8;
        s[1] = (self.0[0] >> 8) as u8;
        s[2] = (self.0[0] >> 16) as u8;
        s[3] = (self.0[0] >> 24) as u8;
        s[4] = (self.0[0] >> 32) as u8;
        s[5] = (self.0[0] >> 40) as u8;
        s[6] = ((self.0[0] >> 48) | (self.0[1] << 4)) as u8;
        s[7] = (self.0[1] >> 4) as u8;
        s[8] = (self.0[1] >> 12) as u8;
        s[9] = (self.0[1] >> 20) as u8;
        s[10] = (self.0[1] >> 28) as u8;
        s[11] = (self.0[1] >> 36) as u8;
        s[12] = (self.0[1] >> 44) as u8;
        s[13] = self.0[2] as u8;
        s[14] = (self.0[2] >> 8) as u8;
        s[15] = (self.0[2] >> 16) as u8;
        s[16] = (self.0[2] >> 24) as u8;
        s[17] = (self.0[2] >> 32) as u8;
        s[18] = (self.0[2] >> 40) as u8;
        s[19] = ((self.0[2] >> 48) | (self.0[3] << 4)) as u8;
        s[20] = (self.0[3] >> 4) as u8;
        s[21] = (self.0[3] >> 12) as u8;
        s[22] = (self.0[3] >> 20) as u8;
        s[23] = (self.0[3] >> 28) as u8;
        s[24] = (self.0[3] >> 36) as u8;
        s[25] = (self.0[3] >> 44) as u8;
        s[26] = self.0[4] as u8;
        s[27] = (self.0[4] >> 8) as u8;
        s[28] = (self.0[4] >> 16) as u8;
        s[29] = (self.0[4] >> 24) as u8;
        s[30] = (self.0[4] >> 32) as u8;
        s[31] = (self.0[4] >> 40) as u8;

        s
    }

    /// Returns `true` iff the scalar is greater than zero.
    #[inline]
    pub fn is_pos(&self) -> bool {
        self.0[0] & 1 == 0
    }

    /// Returns the absolute value of the scalar.
    #[inline]
    pub fn abs(&self) -> Scalar {
        if self.is_pos() {
            *self
        } else {
            -self
        }
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
        let bits_11 = montgomery_mul(&bits_10, bits_1);
        let bits_101 = montgomery_mul(&bits_10, &bits_11);
        let bits_111 = montgomery_mul(&bits_10, &bits_101);
        let bits_1001 = montgomery_mul(&bits_10, &bits_111);
        let bits_1011 = montgomery_mul(&bits_10, &bits_1001);
        let bits_1111 = montgomery_mul(&bits_100, &bits_1011);

        // _10000
        let mut y = montgomery_mul(&bits_1111, bits_1);

        #[inline]
        fn square_multiply(y: &mut Scalar, squarings: usize, x: &Scalar) {
            for _ in 0..squarings {
                *y = y.montgomery_square();
            }
            *y = montgomery_mul(y, x);
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
        montgomery_reduce(&square_internal(self))
    }

    /// Puts a scalar in to Montgomery form, i.e. computes `a*R (mod l)`
    #[inline(never)]
    fn montgomerize(&self) -> Scalar {
        montgomery_mul(self, &RR)
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

    fn reduce(&self) -> Scalar {
        montgomery_reduce(&mul_internal(self, &R))
    }
}

impl Add for &Scalar {
    type Output = Scalar;

    fn add(self, rhs: Self) -> Self::Output {
        let mut sum = Scalar::ZERO;
        let mask = (1u64 << 52) - 1;

        // a + b
        let mut carry: u64 = 0;
        for i in 0..5 {
            carry = self.0[i] + rhs.0[i] + (carry >> 52);
            sum.0[i] = carry & mask;
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
        for i in 0..5 {
            borrow = self.0[i].wrapping_sub(rhs.0[i] + (borrow >> 63));
            difference.0[i] = borrow & mask;
        }

        // conditionally add l if the difference is negative
        let underflow_mask = ((borrow >> 63) ^ 1).wrapping_sub(1);
        let mut carry: u64 = 0;
        for i in 0..5 {
            carry = (carry >> 52) + difference.0[i] + (L.0[i] & underflow_mask);
            difference.0[i] = carry & mask;
        }

        difference
    }
}

impl Mul for &Scalar {
    type Output = Scalar;

    fn mul(self, rhs: Self) -> Self::Output {
        let ab = montgomery_reduce(&mul_internal(self, rhs));
        montgomery_reduce(&mul_internal(&ab, &RR))
    }
}

impl Neg for &Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        &Scalar::ZERO - &montgomery_reduce(&mul_internal(self, &R))
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
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

/// Compute `a^2`
#[inline(always)]
fn square_internal(a: &Scalar) -> [u128; 9] {
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

/// u64 * u64 = u128 multiply helper
#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    (x as u128) * (y as u128)
}

/// Compute `limbs/R` (mod l), where R is the Montgomery modulus 2^260
#[inline(always)]
fn montgomery_reduce(limbs: &[u128; 9]) -> Scalar {
    #[inline(always)]
    fn part1(sum: u128) -> (u128, u64) {
        let p = (sum as u64).wrapping_mul(LFACTOR) & ((1u64 << 52) - 1);
        ((sum + m(p, L.0[0])) >> 52, p)
    }

    #[inline(always)]
    fn part2(sum: u128) -> (u128, u64) {
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

/// Compute `a * b`
#[inline(always)]
fn mul_internal(a: &Scalar, b: &Scalar) -> [u128; 9] {
    let mut z = [0u128; 9];

    z[0] = m(a.0[0], b.0[0]);
    z[1] = m(a.0[0], b.0[1]) + m(a.0[1], b.0[0]);
    z[2] = m(a.0[0], b.0[2]) + m(a.0[1], b.0[1]) + m(a.0[2], b.0[0]);
    z[3] = m(a.0[0], b.0[3]) + m(a.0[1], b.0[2]) + m(a.0[2], b.0[1]) + m(a.0[3], b.0[0]);
    z[4] = m(a.0[0], b.0[4])
        + m(a.0[1], b.0[3])
        + m(a.0[2], b.0[2])
        + m(a.0[3], b.0[1])
        + m(a.0[4], b.0[0]);
    z[5] = m(a.0[1], b.0[4]) + m(a.0[2], b.0[3]) + m(a.0[3], b.0[2]) + m(a.0[4], b.0[1]);
    z[6] = m(a.0[2], b.0[4]) + m(a.0[3], b.0[3]) + m(a.0[4], b.0[2]);
    z[7] = m(a.0[3], b.0[4]) + m(a.0[4], b.0[3]);
    z[8] = m(a.0[4], b.0[4]);

    z
}

#[inline(always)]
fn montgomery_mul(a: &Scalar, b: &Scalar) -> Scalar {
    montgomery_reduce(&mul_internal(a, b))
}

/// `R` = R % L where R = 2^260
const R: Scalar = Scalar([
    0x000f48bd6721e6ed,
    0x0003bab5ac67e45a,
    0x000fffffeb35e51b,
    0x000fffffffffffff,
    0x00000fffffffffff,
]);

/// `RR` = (R^2) % L where R = 2^260
const RR: Scalar = Scalar([
    0x0009d265e952d13b,
    0x000d63c715bea69f,
    0x0005be65cb687604,
    0x0003dceec73d217f,
    0x000009411b7c309a,
]);

/// `L` * `LFACTOR` = -1 (mod 2^52)
const LFACTOR: u64 = 0x51da312547e1b;

/// `L` is the order of base point, i.e. 2^252 + 27742317777372353535851937790883648493
const L: Scalar = Scalar([
    0x0002631a5cf5d3ed,
    0x000dea2f79cd6581,
    0x000000000014def9,
    0x0000000000000000,
    0x0000100000000000,
]);

#[cfg(test)]
mod tests {
    use super::*;

    /// Note: x is 2^253-1 which is slightly larger than the largest scalar produced by
    /// this implementation (l-1), and should show there are no overflows for valid scalars
    ///
    /// x = 14474011154664524427946373126085988481658748083205070504932198000989141204991
    /// x = 7237005577332262213973186563042994240801631723825162898930247062703686954002 mod l
    /// x = 3057150787695215392275360544382990118917283750546154083604586903220563173085*R mod l in Montgomery form
    const X: Scalar = Scalar([
        0x000fffffffffffff,
        0x000fffffffffffff,
        0x000fffffffffffff,
        0x000fffffffffffff,
        0x00001fffffffffff,
    ]);

    /// y = 6145104759870991071742105800796537629880401874866217824609283457819451087098
    const Y: Scalar = Scalar([
        0x000b75071e1458fa,
        0x000bf9d75e1ecdac,
        0x000433d2baf0672b,
        0x0005fffcc11fad13,
        0x00000d96018bb825,
    ]);

    /// x*y = 36752150652102274958925982391442301741 mod l
    const XY: Scalar = Scalar([
        0x000ee6d76ba7632d,
        0x000ed50d71d84e02,
        0x00000000001ba634,
        0x0000000000000000,
        0x0000000000000000,
    ]);

    /// a = 2351415481556538453565687241199399922945659411799870114962672658845158063753
    const A: Scalar = Scalar([
        0x0005236c07b3be89,
        0x0001bc3d2a67c0c4,
        0x000a4aa782aae3ee,
        0x0006b3f6e4fec4c4,
        0x00000532da9fab8c,
    ]);

    /// b = 4885590095775723760407499321843594317911456947580037491039278279440296187236
    const B: Scalar = Scalar([
        0x000d3fae55421564,
        0x000c2df24f65a4bc,
        0x0005b5587d69fb0b,
        0x00094c091b013b3b,
        0x00000acd25605473,
    ]);

    /// a+b = 0
    /// a-b = 4702830963113076907131374482398799845891318823599740229925345317690316127506
    pub static AB: Scalar = Scalar([
        0x000a46d80f677d12,
        0x0003787a54cf8188,
        0x0004954f0555c7dc,
        0x000d67edc9fd8989,
        0x00000a65b53f5718,
    ]);

    #[test]
    fn unpacking() {
        let b = [22u8; 32];
        let d = Scalar::from_bits(&b);
        let b_p = d.as_bytes();

        assert_eq!(b, b_p);
    }

    #[test]
    fn add() {
        let res = &A + &B;
        let zero = Scalar::ZERO;

        for i in 0..5 {
            assert_eq!(res.0[i], zero.0[i]);
        }
    }

    #[test]
    fn sub() {
        let res = &A - &B;
        for i in 0..5 {
            assert_eq!(res.0[i], AB.0[i]);
        }
    }

    #[test]
    fn mul() {
        let res = &X * &Y;
        for i in 0..5 {
            assert_eq!(res.0[i], XY.0[i]);
        }
    }

    #[test]
    fn invert() {
        // x = 2238329342913194256032495932344128051776374960164957527413114840482143558222
        let x = Scalar::from_bits(&[
            0x4e, 0x5a, 0xb4, 0x34, 0x5d, 0x47, 0x08, 0x84, 0x59, 0x13, 0xb4, 0x64, 0x1b, 0xc2,
            0x7d, 0x52, 0x52, 0xa5, 0x85, 0x10, 0x1b, 0xcc, 0x42, 0x44, 0xd4, 0x49, 0xf4, 0xa8,
            0x79, 0xd9, 0xf2, 0x04,
        ]);

        // 1/x = 6859937278830797291664592131120606308688036382723378951768035303146619657244
        let x_inv = Scalar::from_bits(&[
            0x1c, 0xdc, 0x17, 0xfc, 0xe0, 0xe9, 0xa5, 0xbb, 0xd9, 0x24, 0x7e, 0x56, 0xbb, 0x01,
            0x63, 0x47, 0xbb, 0xba, 0x31, 0xed, 0xd5, 0xa9, 0xbb, 0x96, 0xd5, 0x0b, 0xcd, 0x7a,
            0x3f, 0x96, 0x2a, 0x0f,
        ]);

        let res = x.invert();
        for i in 0..5 {
            assert_eq!(res.0[i], x_inv.0[i]);
        }

        let res = &res * &x;
        for i in 0..5 {
            assert_eq!(res.0[i], Scalar::ONE.0[i]);
        }
    }
}
