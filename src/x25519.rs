use crate::fe25519;
use crate::point;
use crate::scalar;

pub fn dh_keygen(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut sk = *seed;
    scalar::clamp(&mut sk);

    let d = scalar::get32(&sk);
    let q = point::ladder_base(&d);

    let pk = fe25519::pack(&q);

    (sk, pk)
}

pub fn dh_exchange(pk: &[u8; 32], sk: &[u8; 32]) -> [u8; 32] {
    let rx = fe25519::unpack(pk);
    let d = scalar::get32(sk);
    let ss = point::ladder(&rx, &d);
    fe25519::pack(&ss)
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use super::*;

    #[test]
    fn dh_kat() {
        let seed = [
            0x05, 0xaa, 0xb7, 0x28, 0xaf, 0x33, 0x72, 0xef, 0x55, 0xd3, 0x84, 0x90, 0xa7, 0x0a,
            0x3b, 0xd1, 0xce, 0xdd, 0xdc, 0xf6, 0x25, 0x25, 0x6f, 0xf0, 0x38, 0x5b, 0xd9, 0x6d,
            0xf9, 0xd5, 0xaa, 0x13,
        ];
        let pk = [
            0xfc, 0x35, 0x46, 0x77, 0x33, 0xcc, 0x25, 0xd3, 0x47, 0x06, 0x07, 0x32, 0x60, 0x8e,
            0x12, 0x58, 0xd4, 0x85, 0x45, 0x76, 0x15, 0x10, 0xfa, 0xe0, 0x14, 0x08, 0x3e, 0x20,
            0x9c, 0x8e, 0xb5, 0x33,
        ];
        let sk = [
            0x00, 0xaa, 0xb7, 0x28, 0xaf, 0x33, 0x72, 0xef, 0x55, 0xd3, 0x84, 0x90, 0xa7, 0x0a,
            0x3b, 0xd1, 0xce, 0xdd, 0xdc, 0xf6, 0x25, 0x25, 0x6f, 0xf0, 0x38, 0x5b, 0xd9, 0x6d,
            0xf9, 0xd5, 0xaa, 0x53,
        ];

        let (sk_a, pk_a) = dh_keygen(&seed);

        assert_eq!(sk, sk_a);
        assert_eq!(pk, pk_a);

        let ss = [
            0xc7, 0xe3, 0x9e, 0x20, 0x91, 0xe8, 0x63, 0x8b, 0x6c, 0x1c, 0xf3, 0x82, 0xbd, 0xd7,
            0xb2, 0x8e, 0x8a, 0x1e, 0x64, 0xbc, 0x2f, 0x2c, 0x8e, 0x0f, 0x80, 0xda, 0x1f, 0x13,
            0x52, 0xbd, 0x66, 0x61,
        ];

        let ss_a = dh_exchange(&pk, &sk);

        assert_eq!(ss, ss_a);
    }

    #[test]
    fn dh_round_trip() {
        for _ in 0..1000 {
            let (sk_a, pk_a) = dh_keygen(&thread_rng().gen());
            let (sk_b, pk_b) = dh_keygen(&thread_rng().gen());

            let ss_a = dh_exchange(&pk_b, &sk_a);
            let ss_b = dh_exchange(&pk_a, &sk_b);
            let ss_c = dh_exchange(&pk_a, &sk_a);

            assert_eq!(ss_a, ss_b);
            assert_ne!(ss_a, ss_c);
        }
    }

    #[test]
    fn dh_interop() {
        for _ in 0..1000 {
            let (sk_a, pk_a) = dh_keygen(&thread_rng().gen());
            let (sk_b, pk_b) = dh_keygen(&thread_rng().gen());

            let ss_a = dh_exchange(&pk_b, &sk_a);

            let pk_a = orion::kex::PublicKey::from(pk_a);
            let sk_b = orion::hazardous::ecc::x25519::PrivateKey::from(sk_b);
            let ss_b = orion::hazardous::ecc::x25519::key_agreement(&sk_b, &pk_a).unwrap();

            assert_eq!(ss_b, &ss_a[..]);
        }
    }
}
