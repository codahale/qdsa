use crate::point::Point;
use crate::scalar::Scalar;

/// Given a public key `pk` and secret key `sk`, returns the X25519 shared secret.
#[must_use]
pub fn x25519(pk: &[u8; 32], sk: &[u8; 32]) -> [u8; 32] {
    let q = Point::from_bytes(pk);
    let d = Scalar::clamp(sk);
    (&q * &d).as_bytes()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rand::{thread_rng, Rng};

    use crate::public_key;

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
}
