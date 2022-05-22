use std::ops::{Add, Mul, Neg, Sub};

use zeroize::Zeroize;

/// A scalar value of Curve25519.
#[derive(Copy, Clone, Default)]
pub struct Scalar(pub(crate) [u16; 32]);

impl Scalar {
    /// Clamps the given byte array and returns a valid [Scalar].
    #[inline]
    pub fn clamp(x: &[u8; 32]) -> Scalar {
        let mut x = *x;
        x[0] &= 248;
        x[31] &= 127;
        x[31] |= 64;

        Scalar::from_bits(&x)
    }

    /// Reduces the given little-endian array modulo `l`.
    #[inline]
    pub fn reduce(x: &[u8; 32]) -> Scalar {
        let mut d = Scalar::from_bits(x);
        reduce_add_sub(&mut d);
        d
    }

    /// Reduces the given little-endian array modulo `l`.
    #[inline]
    pub fn wide_reduce(x: &[u8; 64]) -> Scalar {
        let mut t = [0u32; 64];
        for (a, b) in t.iter_mut().zip(x.iter()) {
            *a = *b as u32
        }
        barrett_reduce(&t)
    }

    /// Returns the scalar as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut x = [0u8; 32];
        for (a, b) in self.0.iter().zip(x.iter_mut()) {
            *b = *a as u8;
        }
        x
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

    #[inline]
    fn from_bits(x: &[u8; 32]) -> Scalar {
        let mut d = Scalar::default();
        for (a, b) in d.0.iter_mut().zip(x.iter()) {
            *a = *b as u16
        }
        d
    }
}

impl Add for &Scalar {
    type Output = Scalar;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let mut r = Scalar::default();
        for ((a, &b), &c) in r.0.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            *a = b.wrapping_add(c);
        }
        for i in 0..31 {
            let carry = r.0[i] >> 8;
            r.0[i + 1] = r.0[i + 1].wrapping_add(carry);
            r.0[i] &= 0xff;
        }
        reduce_add_sub(&mut r);
        r
    }
}

impl Neg for &Scalar {
    type Output = Scalar;

    #[inline]
    fn neg(self) -> Self::Output {
        let mut d = Scalar::default();
        let mut b = 0;

        for ((&m_i, y_i), d_i) in M.iter().zip(self.0).zip(d.0.iter_mut()) {
            let t = m_i.wrapping_sub(y_i as u32).wrapping_sub(b);
            *d_i = (t & 255) as u16;
            b = (t >> 8) & 1;
        }

        d
    }
}

impl Sub for &Scalar {
    type Output = Scalar;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        self + &(-rhs)
    }
}

impl Mul for &Scalar {
    type Output = Scalar;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let mut t = [0u32; 64];
        for i in 0..32 {
            for j in 0..32 {
                t[i + j] += self.0[i] as u32 * rhs.0[j] as u32;
            }
        }

        /* Reduce coefficients */
        for i in 0..63 {
            let carry = t[i] >> 8;
            t[i + 1] += carry;
            t[i] &= 0xff;
        }

        barrett_reduce(&t)
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

const M: [u32; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

const MU: [u32; 33] = [
    0x1b, 0x13, 0x2c, 0x0a, 0xa3, 0xe5, 0x9c, 0xed, 0xa7, 0x29, 0x63, 0x08, 0x5d, 0x21, 0x06, 0x21,
    0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x0f,
];

fn barrett_reduce(x: &[u32; 64]) -> Scalar {
    let mut r = Scalar::default();
    let mut q2 = [0u32; 66];
    let mut r1 = [0u32; 33];
    let mut r2 = [0u32; 33];
    let mut pb = 0;

    for i in 0..33 {
        for j in 0..33 {
            if i + j >= 31 {
                q2[i + j] += MU[i] * x[j + 31]
            }
        }
    }
    let carry = q2[31] >> 8;
    q2[32] += carry;
    let carry = q2[32] >> 8;
    q2[33] += carry;

    r1.copy_from_slice(&x[0..33]);
    for i in 0..32 {
        for j in 0..33 {
            if i + j < 33 {
                r2[i + j] += M[i] * q2[j + 33];
            }
        }
    }

    for i in 0..32 {
        let carry = r2[i] >> 8;
        r2[i + 1] += carry;
        r2[i] &= 0xff;
    }

    for i in 0..32 {
        pb += r2[i];
        let b = lt(r1[i], pb);
        r.0[i] = (r1[i].wrapping_sub(pb + (b << 8))) as u8 as u16;
        pb = b;
    }

    /* XXX: Can it really happen that r<0?, See HAC, Alg 14.42, Step 3
     * If so: Handle  it here!
     */

    reduce_add_sub(&mut r);
    reduce_add_sub(&mut r);

    r
}

#[inline]
fn lt(a: u32, b: u32) -> u32 {
    let mut x = a;
    x = x.wrapping_sub(b); // 0..65535: no; 4294901761..4294967295: yes
    x >>= 31; // 0: no; 1: yes
    x
}

#[inline]
// Reduce coefficients of r before calling reduce_add_sub
fn reduce_add_sub(r: &mut Scalar) {
    let mut pb = 0;
    let mut b = 0;
    let mut t = [0u8; 32];

    for i in 0..32 {
        pb += M[i];
        b = lt(r.0[i] as u32, pb);
        t[i] = ((r.0[i] as u32).wrapping_sub(pb + (b << 8))) as u8;
        pb = b;
    }

    let mask = b.wrapping_sub(1);

    for (&t_i, r_i) in t.iter().zip(r.0.iter_mut()) {
        *r_i ^= (mask & (*r_i as u32 ^ t_i as u32)) as u16;
    }
}

#[cfg(test)]
mod tests {}
