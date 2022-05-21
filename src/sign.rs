use sha3::Digest;
use sha3::Sha3_512;

use crate::fe25519::Fe25519;
use crate::point::Point;
use crate::{fe25519, point, scalar};

// verified
pub fn keypair(seed: &[u8; 32]) -> ([u8; 64], [u8; 32]) {
    let mut sk = hash(seed);
    sk[32] &= 248;
    sk[63] &= 127;
    sk[63] |= 64;

    let d = scalar::get32(&sk[32..].try_into().unwrap());
    let r = point::ladder_base(&d);

    (sk, fe25519::pack(&point::compress(&r)))
}

// verified
pub fn sign(m: &[u8], pk: &[u8; 32], sk: &[u8; 64]) -> [u8; 64] {
    let mut sm = Vec::with_capacity(m.len() + 32);
    sm.extend(&sk[..32]);
    sm.extend(m);

    let r = hash(&sm);
    let r = scalar::get64(&r);
    let rx = fe25519::pack(&point::compress(&point::ladder_base(&r)));

    sm.clear();
    sm.extend(&rx);
    sm.extend(pk);
    sm.extend(m);
    let h = scalar::get64(&hash(&sm));
    let h = scalar::abs(&h);
    let s = scalar::get32(&sk[32..].try_into().unwrap());
    let s = scalar::mul(&h, &s);
    let s = scalar::sub(&r, &s);

    sm.clear();
    sm.extend(&rx);
    sm.extend(scalar::pack(&s));
    sm.try_into().unwrap()
}

pub fn verify(m: &[u8], sig: &[u8; 64], pk: &[u8; 32]) -> bool {
    let rx = fe25519::unpack(&sig[..32].try_into().unwrap());
    let s = scalar::get32(&sig[32..].try_into().unwrap());

    let mut sm = Vec::new();
    sm.extend(&sig[..32]);
    sm.extend(pk);
    sm.extend(m);
    let h = scalar::get64(&hash(&sm));

    let pkx = fe25519::unpack(pk);
    let mut s_p = point::decompress(&pkx);
    let mut h_q = Point::default();
    point::ladder(&mut h_q, &mut s_p, &pkx, &h);
    let s_p = point::ladder_base(&s);

    let mut bzz = Fe25519::default();
    let mut bxz = Fe25519::default();
    let mut bxx = Fe25519::default();

    point::b_values(&mut bzz, &mut bxz, &mut bxx, &s_p, &h_q);

    // ABOVE THIS LINE IS GOOD

    point::check(&bzz, &bxz, &bxx, &rx)
}

fn hash(bin: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(bin);
    hasher.finalize().into()
}

//
// pub fn qdsa_sign<F>(sk: &[u8; 32], pk: &[u8; 32], r: &[u8; 32], mut hash: F) -> [u8; 64]
// where
//     F: FnMut(&[u8; 32], &[u8; 32]) -> [u8; 32],
// {
//     todo!()
// }
//
// pub fn qdsa_verify<F>(pk: &[u8; 32], r: &[u8; 32], sig: &[u8; 64], mut hash: F) -> [u8; 64]
// where
//     F: FnMut(&[u8; 32], &[u8; 32]) -> [u8; 32],
// {
//     todo!()
// }

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use super::*;

    #[test]
    fn qdsa_round_trip() {
        for _ in 0..1000 {
            let (sk_a, pk_a) = keypair(&thread_rng().gen());
            let (_, pk_b) = keypair(&thread_rng().gen());

            let message = b"this is a message";

            let sig = sign(message, &pk_a, &sk_a);
            let mut sig_p = sig;
            sig_p[4] ^= 1;

            assert!(verify(message, &sig, &pk_a));
            assert!(!verify(message, &sig, &pk_b));
            assert!(!verify(b"this is a different message", &sig, &pk_a));
            assert!(!verify(message, &sig_p, &pk_a));
        }
    }
}
