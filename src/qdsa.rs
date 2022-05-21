use crate::{fe25519, point, scalar};

pub fn keypair(
    seed: &[u8; 32],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> ([u8; 64], [u8; 32]) {
    let mut sk = hash(&[seed]);
    scalar::clamp(&mut sk[32..]);

    let d = scalar::get32(&sk[32..].try_into().unwrap());
    let r = point::ladder_base(&d);

    (sk, fe25519::pack(&r))
}

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
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake128,
    };

    use super::*;

    fn shake128(bin: &[&[u8]]) -> [u8; 64] {
        let mut hasher = Shake128::default();
        for data in bin {
            hasher.update(data);
        }

        let mut digest = [0u8; 64];
        let mut xof = hasher.finalize_xof();
        xof.read(&mut digest);
        digest
    }

    #[test]
    fn qdsa_round_trip() {
        for _ in 0..1000 {
            let (sk_a, pk_a) = keypair(&thread_rng().gen(), shake128);
            let (_, pk_b) = keypair(&thread_rng().gen(), shake128);

            let message = b"this is a message";

            let sig = sign(message, &pk_a, &sk_a, shake128);
            let mut sig_p = sig;
            sig_p[4] ^= 1;

            assert!(verify(message, &sig, &pk_a, shake128));
            assert!(!verify(message, &sig, &pk_b, shake128));
            assert!(!verify(
                b"this is a different message",
                &sig,
                &pk_a,
                shake128
            ));
            assert!(!verify(message, &sig_p, &pk_a, shake128));
        }
    }
}
