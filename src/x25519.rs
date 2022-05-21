use crate::fe25519;
use crate::point;
use crate::scalar;

/// Given a secret key `sk`, returns the corresponding public key.
pub fn public_key(sk: &[u8; 32]) -> [u8; 32] {
    let mut sk = *sk;
    scalar::clamp(&mut sk);

    let d = scalar::get32(&sk);
    let q = point::ladder_base(&d);

    fe25519::pack(&q)
}

/// Given a public key `pk` and secret key `sk`, returns the X25519 shared secret.
#[must_use]
pub fn x25519(pk: &[u8; 32], sk: &[u8; 32]) -> [u8; 32] {
    let mut sk = *sk;
    scalar::clamp(&mut sk);

    let rx = fe25519::unpack(pk);
    let d = scalar::get32(&sk);
    fe25519::pack(&point::ladder(&rx, &d))
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rand::{thread_rng, Rng};

    use super::*;

    #[test]
    fn rfc7748_test_vectors() {
        // https://datatracker.ietf.org/doc/html/rfc7748#section-5.2

        let sk = hex!("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let pk = hex!("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let ss = hex!("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        assert_eq!(ss, x25519(&pk, &sk));

        let sk = hex!("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let pk = hex!("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let ss = hex!("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

        assert_eq!(ss, x25519(&pk, &sk));
    }

    #[test]
    fn x25519_kat() {
        let sk = [
            0x05, 0xaa, 0xb7, 0x28, 0xaf, 0x33, 0x72, 0xef, 0x55, 0xd3, 0x84, 0x90, 0xa7, 0x0a,
            0x3b, 0xd1, 0xce, 0xdd, 0xdc, 0xf6, 0x25, 0x25, 0x6f, 0xf0, 0x38, 0x5b, 0xd9, 0x6d,
            0xf9, 0xd5, 0xaa, 0x13,
        ];
        let pk = [
            0xfc, 0x35, 0x46, 0x77, 0x33, 0xcc, 0x25, 0xd3, 0x47, 0x06, 0x07, 0x32, 0x60, 0x8e,
            0x12, 0x58, 0xd4, 0x85, 0x45, 0x76, 0x15, 0x10, 0xfa, 0xe0, 0x14, 0x08, 0x3e, 0x20,
            0x9c, 0x8e, 0xb5, 0x33,
        ];

        assert_eq!(pk, public_key(&sk));

        let ss = [
            0xc7, 0xe3, 0x9e, 0x20, 0x91, 0xe8, 0x63, 0x8b, 0x6c, 0x1c, 0xf3, 0x82, 0xbd, 0xd7,
            0xb2, 0x8e, 0x8a, 0x1e, 0x64, 0xbc, 0x2f, 0x2c, 0x8e, 0x0f, 0x80, 0xda, 0x1f, 0x13,
            0x52, 0xbd, 0x66, 0x61,
        ];

        assert_eq!(ss, x25519(&pk, &sk));
    }

    #[test]
    fn dh_round_trip() {
        for _ in 0..1000 {
            let sk_a = thread_rng().gen();
            let pk_a = public_key(&sk_a);

            let sk_b = thread_rng().gen();
            let pk_b = public_key(&sk_b);

            let ss_a = x25519(&pk_b, &sk_a);
            let ss_b = x25519(&pk_a, &sk_b);
            let ss_c = x25519(&pk_a, &sk_a);

            assert_eq!(ss_a, ss_b);
            assert_ne!(ss_a, ss_c);
        }
    }

    #[test]
    fn dh_interop() {
        for _ in 0..1000 {
            let sk_a = thread_rng().gen();
            let pk_a = public_key(&sk_a);

            let sk_b = thread_rng().gen();
            let pk_b = public_key(&sk_b);

            let ss_a = x25519(&pk_b, &sk_a);

            let pk_a = orion::kex::PublicKey::from(pk_a);
            let sk_b = orion::hazardous::ecc::x25519::PrivateKey::from(sk_b);
            let ss_b = orion::hazardous::ecc::x25519::key_agreement(&sk_b, &pk_a).unwrap();

            assert_eq!(ss_b, &ss_a[..]);
        }
    }
}
