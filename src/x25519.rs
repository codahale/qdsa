//! The X25519 Diffie-Hellman key agreement algorithm, per
//! [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748).

use subtle::{ConstantTimeEq, CtOption};

use crate::point::Point;
use crate::scalar::Scalar;

/// Computes the X25519 shared secret for public key `pk` and secret key `sk`.
///
/// *N.B.:* Does not check for contributory behavior. Use [x25519_strict] unless your usage does not
/// require that.
#[must_use]
pub fn x25519(pk: &[u8; 32], sk: &[u8; 32]) -> [u8; 32] {
    let d = Scalar::clamp(sk);
    let q = Point::from_bytes(pk);
    (&q * &d).as_bytes()
}

/// Computes the X25519 shared secret for public key `pk` and secret key `sk`, checking for
/// contributory behavior.
///
/// Returns `None` if `pk` is non-canonical, low-order, or small-group.
#[must_use]
pub fn x25519_strict(pk: &[u8; 32], sk: &[u8; 32]) -> Option<[u8; 32]> {
    let ss = x25519(pk, sk);
    CtOption::new(ss, !ss.ct_eq(&[0u8; 32])).into()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use wycheproof::xdh::{TestFlag, TestName, TestSet};

    use super::*;

    #[test]
    fn rfc7748_test_vectors() {
        // https://datatracker.ietf.org/doc/html/rfc7748#section-5.2

        assert_eq!(
            hex!("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
            x25519(
                &hex!("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
                &hex!("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            )
        );

        assert_eq!(
            hex!("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
            x25519(
                &hex!("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
                &hex!("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            )
        );

        assert_eq!(
            hex!("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"),
            x25519(
                &hex!("0900000000000000000000000000000000000000000000000000000000000000"),
                &hex!("0900000000000000000000000000000000000000000000000000000000000000"),
            )
        );

        let k = hex!("0900000000000000000000000000000000000000000000000000000000000000");
        let u = hex!("0900000000000000000000000000000000000000000000000000000000000000");
        let (k_1_000, _) = (0..1_000).fold((k, u), |(k, u), _| (x25519(&u, &k), k));
        assert_eq!(
            hex!("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"),
            k_1_000,
        );

        // this passes but takes ~10min to run
        // let k = hex!("0900000000000000000000000000000000000000000000000000000000000000");
        // let u = hex!("0900000000000000000000000000000000000000000000000000000000000000");
        // let (k_1_000_000, _) = (0..1_000_000).fold((k, u), |(k, u), _| (x25519(&u, &k), k));
        // assert_eq!(
        //     hex!("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"),
        //     k_1_000_000,
        // );
    }

    #[test]
    fn wycheproof_test_vectors() {
        let test_set =
            TestSet::load(TestName::X25519).expect("unable to load Wycheproof test vectors");

        for g in test_set.test_groups {
            for t in g.tests {
                let sk: [u8; 32] = t.private_key.try_into().expect("invalid scalar len");
                let pk: [u8; 32] = t.public_key.try_into().expect("invalid point len");
                let ss: [u8; 32] = t.shared_secret.try_into().expect("invalid point len");

                let ss_p = x25519(&pk, &sk);
                assert_eq!(&ss, &ss_p, "error for {}", t.tc_id);

                if t.flags.contains(&TestFlag::ZeroSharedSecret) {
                    assert_eq!(None, x25519_strict(&pk, &sk), "error for {}", t.tc_id);
                }
            }
        }
    }
}
