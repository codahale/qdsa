pub type GroupScalar = [u16; 32];

const M: [u32; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

const MU: [u32; 33] = [
    0x1b, 0x13, 0x2c, 0x0a, 0xa3, 0xe5, 0x9c, 0xed, 0xa7, 0x29, 0x63, 0x08, 0x5d, 0x21, 0x06, 0x21,
    0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x0f,
];

// verified
pub fn clamp(sk: &mut [u8; 32]) {
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
}

// verified
pub fn get32(x: &[u8; 32]) -> GroupScalar {
    let mut d = GroupScalar::default();
    for (a, b) in d.iter_mut().zip(x.iter()) {
        *a = *b as u16
    }
    d
}

// verified
pub fn get64(x: &[u8; 64]) -> GroupScalar {
    let mut t = [0u32; 64];
    for (a, b) in t.iter_mut().zip(x.iter()) {
        *a = *b as u32
    }
    barrett_reduce(&t)
}

// verified
pub fn pack(r: &GroupScalar) -> [u8; 32] {
    let mut x = [0u8; 32];
    for (a, b) in r.iter().zip(x.iter_mut()) {
        *b = *a as u8;
    }
    x
}

// verified
fn add(x: &GroupScalar, y: &GroupScalar) -> GroupScalar {
    let mut r = [0u16; 32];
    for ((a, &b), &c) in r.iter_mut().zip(x.iter()).zip(y.iter()) {
        *a = b.wrapping_add(c);
    }
    for i in 0..31 {
        let carry = r[i] >> 8;
        r[i + 1] = r[i + 1].wrapping_add(carry);
        r[i] &= 0xff;
    }
    reduce_add_sub(&mut r);
    r
}

// verified
pub fn sub(x: &GroupScalar, y: &GroupScalar) -> GroupScalar {
    let mut d = GroupScalar::default();
    let mut b = 0;
    for i in 0..32 {
        let t = M[i].wrapping_sub(y[i] as u32).wrapping_sub(b);
        d[i] = (t & 255) as u16;
        b = (t >> 8) & 1;
    }
    add(x, &d)
}

// verified
pub fn mul(x: &GroupScalar, y: &GroupScalar) -> GroupScalar {
    let mut t = [0u32; 64];
    for i in 0..32 {
        for j in 0..32 {
            t[i + j] += x[i] as u32 * y[j] as u32;
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

// verified
fn negate(r: &GroupScalar) -> GroupScalar {
    let zero = GroupScalar::default();
    sub(&zero, r)
}

// verified
pub fn abs(r: &GroupScalar) -> GroupScalar {
    if r[0] & 1 == 0 {
        *r
    } else {
        negate(r)
    }
}

// verified
fn barrett_reduce(x: &[u32; 64]) -> GroupScalar {
    let mut r = GroupScalar::default();
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
        r[i] = (r1[i].wrapping_sub(pb + (b << 8))) as u8 as u16;
        pb = b;
    }

    /* XXX: Can it really happen that r<0?, See HAC, Alg 14.42, Step 3
     * If so: Handle  it here!
     */

    reduce_add_sub(&mut r);
    reduce_add_sub(&mut r);

    r
}

// verified
fn lt(a: u32, b: u32) -> u32 {
    let mut x = a;
    x = x.wrapping_sub(b); // 0..65535: no; 4294901761..4294967295: yes
    x >>= 31; // 0: no; 1: yes
    x
}

// Reduce coefficients of r before calling reduce_add_sub
// verified
fn reduce_add_sub(r: &mut GroupScalar) {
    let mut pb = 0;
    let mut b = 0;
    let mut t = [0u8; 32];

    for i in 0..32 {
        pb += M[i];
        b = lt(r[i] as u32, pb);
        t[i] = ((r[i] as u32).wrapping_sub(pb + (b << 8))) as u8;
        pb = b;
    }

    let mask = b.wrapping_sub(1);

    for i in 0..32 {
        r[i] ^= (mask & (r[i] as u32 ^ t[i] as u32)) as u16;
    }
}

#[cfg(test)]
mod tests {}
