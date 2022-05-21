use crate::scalar::Scalar;
use crate::{fe25519, point};

pub fn sign(
    m: &[u8],
    pk: &[u8; 32],
    nonce: &[u8; 32],
    sk: &[u8; 32],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> [u8; 64] {
    let r = hash(&[nonce, m]);
    let r = Scalar::wide_reduce(&r);
    let rx = fe25519::pack(&point::ladder_base(&r));

    let h = Scalar::wide_reduce(&hash(&[&rx, pk, m]));
    let h = h.abs();
    let s = Scalar::clamp(sk);
    let s = &h * &s;
    let s = &r - &s;
    let s = s.abs();

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&rx);
    sig[32..].copy_from_slice(&s.as_bytes());
    sig
}

pub fn verify(
    m: &[u8],
    sig: &[u8; 64],
    pk: &[u8; 32],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> bool {
    let rx = fe25519::unpack(&sig[..32].try_into().unwrap());
    let s = Scalar::reduce(&sig[32..].try_into().unwrap());
    if !s.is_pos() {
        return false;
    }

    let h = Scalar::wide_reduce(&hash(&[&sig[..32], pk, m]));

    let pkx = fe25519::unpack(pk);
    let h_q = point::ladder(&pkx, &h);
    let s_p = point::ladder_base(&s);

    let (bzz, bxz, bxx) = point::b_values(&s_p, &h_q);
    point::check(&bzz, &bxz, &bxx, &rx)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rand::{thread_rng, Rng};
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake128,
    };

    use crate::public_key;

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
    fn sign_kat() {
        let pk = hex!("a8bc0c539775462b2f21834ccddcb3c5d452b6702a85818bba5da1f0c2a90a59");
        let nonce = hex!("221e3ec71706d2568585249a6f6ef7aa8b3ddcf63ffe20560875e2de07668cd3");
        let sk = hex!("a012a86000174e1c3ff635307874bfbc9ae67371f78186ceb58b7df68d4bd25e");
        let m = hex!("4f2b8a8027a8542bda6f");
        let sig = hex!("8137f6865c2a5c74feb9f5a64ae06601ed0878d9bf6be8b8297221034e7bba645a04f337ea101a11352ebb4c377e436b9502520a5e8056f5443ab15d2c25d10b");
        let sig_a = sign(&m, &pk, &nonce, &sk, shake128);
        assert_eq!(sig, sig_a);
    }

    #[test]
    fn qdsa_round_trip() {
        for _ in 0..1000 {
            let sk_a = thread_rng().gen();
            let pk_a = public_key(&sk_a);
            let pk_b = public_key(&thread_rng().gen());
            let nonce = thread_rng().gen();

            let message = b"this is a message";

            let sig = sign(message, &pk_a, &nonce, &sk_a, shake128);
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
