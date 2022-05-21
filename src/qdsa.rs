use crate::{fe25519, point, scalar};

// verified
pub fn keypair(
    seed: &[u8; 32],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> ([u8; 64], [u8; 32]) {
    let mut sk = hash(&[seed]);
    sk[32] &= 248;
    sk[63] &= 127;
    sk[63] |= 64;

    let d = scalar::get32(&sk[32..].try_into().unwrap());
    let r = point::ladder_base(&d);

    (sk, fe25519::pack(&r))
}

// verified
pub fn sign(
    m: &[u8],
    pk: &[u8; 32],
    sk: &[u8; 64],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> [u8; 64] {
    let r = hash(&[&sk[..32], m]);
    let r = scalar::get64(&r);
    let rx = fe25519::pack(&point::ladder_base(&r));

    let h = scalar::get64(&hash(&[&rx, pk, m]));
    let h = scalar::abs(&h);
    let s = scalar::get32(&sk[32..].try_into().unwrap());
    let s = scalar::mul(&h, &s);
    let s = scalar::sub(&r, &s);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&rx);
    sig[32..].copy_from_slice(&scalar::pack(&s));
    sig
}

pub fn verify(
    m: &[u8],
    sig: &[u8; 64],
    pk: &[u8; 32],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> bool {
    let rx = fe25519::unpack(&sig[..32].try_into().unwrap());
    let s = scalar::get32(&sig[32..].try_into().unwrap());

    let h = scalar::get64(&hash(&[&sig[..32], pk, m]));

    let pkx = fe25519::unpack(pk);
    let h_q = point::ladder(&pkx, &h);
    let s_p = point::ladder_base(&s);

    let (bzz, bxz, bxx) = point::b_values(&s_p, &h_q);
    point::check(&bzz, &bxz, &bxx, &rx)
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};
    use sha3::Digest;
    use sha3::Sha3_512;

    use super::*;

    fn sha3_512(bin: &[&[u8]]) -> [u8; 64] {
        let mut hasher = Sha3_512::new();
        for data in bin {
            hasher.update(data);
        }
        hasher.finalize().into()
    }

    #[test]
    fn qdsa_round_trip() {
        for _ in 0..1000 {
            let (sk_a, pk_a) = keypair(&thread_rng().gen(), sha3_512);
            let (_, pk_b) = keypair(&thread_rng().gen(), sha3_512);

            let message = b"this is a message";

            let sig = sign(message, &pk_a, &sk_a, sha3_512);
            let mut sig_p = sig;
            sig_p[4] ^= 1;

            assert!(verify(message, &sig, &pk_a, sha3_512));
            assert!(!verify(message, &sig, &pk_b, sha3_512));
            assert!(!verify(
                b"this is a different message",
                &sig,
                &pk_a,
                sha3_512
            ));
            assert!(!verify(message, &sig_p, &pk_a, sha3_512));
        }
    }
}
