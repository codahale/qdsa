use crate::{fe25519, point, scalar};

pub fn sign(
    m: &[u8],
    pk: &[u8; 32],
    nonce: &[u8; 32],
    sk: &[u8; 32],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> [u8; 64] {
    let mut sk = *sk;
    scalar::clamp(&mut sk);

    let r = hash(&[nonce, m]);
    let r = scalar::get64(&r);
    let rx = fe25519::pack(&point::ladder_base(&r));

    let h = scalar::get64(&hash(&[&rx, pk, m]));
    let h = scalar::abs(&h);
    let s = scalar::get32(&sk);
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
    let s = scalar::get32_reduced(&sig[32..].try_into().unwrap());

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
        let pk = [
            0xa8, 0xbc, 0x0c, 0x53, 0x97, 0x75, 0x46, 0x2b, 0x2f, 0x21, 0x83, 0x4c, 0xcd, 0xdc,
            0xb3, 0xc5, 0xd4, 0x52, 0xb6, 0x70, 0x2a, 0x85, 0x81, 0x8b, 0xba, 0x5d, 0xa1, 0xf0,
            0xc2, 0xa9, 0x0a, 0x59,
        ];
        let nonce = [
            0x22, 0x1e, 0x3e, 0xc7, 0x17, 0x06, 0xd2, 0x56, 0x85, 0x85, 0x24, 0x9a, 0x6f, 0x6e,
            0xf7, 0xaa, 0x8b, 0x3d, 0xdc, 0xf6, 0x3f, 0xfe, 0x20, 0x56, 0x08, 0x75, 0xe2, 0xde,
            0x07, 0x66, 0x8c, 0xd3,
        ];
        let sk = [
            0xa0, 0x12, 0xa8, 0x60, 0x00, 0x17, 0x4e, 0x1c, 0x3f, 0xf6, 0x35, 0x30, 0x78, 0x74,
            0xbf, 0xbc, 0x9a, 0xe6, 0x73, 0x71, 0xf7, 0x81, 0x86, 0xce, 0xb5, 0x8b, 0x7d, 0xf6,
            0x8d, 0x4b, 0xd2, 0x5e,
        ];
        let m = [0x4f, 0x2b, 0x8a, 0x80, 0x27, 0xa8, 0x54, 0x2b, 0xda, 0x6f];
        let sig = [
            0x81, 0x37, 0xf6, 0x86, 0x5c, 0x2a, 0x5c, 0x74, 0xfe, 0xb9, 0xf5, 0xa6, 0x4a, 0xe0,
            0x66, 0x01, 0xed, 0x08, 0x78, 0xd9, 0xbf, 0x6b, 0xe8, 0xb8, 0x29, 0x72, 0x21, 0x03,
            0x4e, 0x7b, 0xba, 0x64, 0x5a, 0x04, 0xf3, 0x37, 0xea, 0x10, 0x1a, 0x11, 0x35, 0x2e,
            0xbb, 0x4c, 0x37, 0x7e, 0x43, 0x6b, 0x95, 0x02, 0x52, 0x0a, 0x5e, 0x80, 0x56, 0xf5,
            0x44, 0x3a, 0xb1, 0x5d, 0x2c, 0x25, 0xd1, 0x0b,
        ];
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
