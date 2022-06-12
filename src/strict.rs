//! An implementation of [qDSA](https://joostrenes.nl/publications/qdsa-eprint.pdf) (aka Quotient
//! DSA) over Curve25519 which eliminates malleability by restriction proof scalars to those with
//! non-zero LSBs.
//!
//! Produces signatures which can be verified with the standard algorithm, but will not verify
//! roughly half of signatures produced with the standard algorithm.

use crate::hazmat::{Point, Scalar, G};

/// Signs a message with the qDSA algorithm.
///
/// In the formal description of the algorithm, a 32-byte secret key is hashed into a 64-byte value:
///
/// ```text
/// d' || d'' = H(k)
/// ```
///
/// For this API, `sk = d'`, `pk = [d']G`, and `nonce = d''`.
///
/// * `pk`: the signer's public key
/// * `sk`: the signer's secret key (i.e. `d''` in the literature)
/// * `nonce`: a pseudorandom secret value (i.e. `d'` in the literature)
/// * `m`: the message to be signed
/// * `hash`: a structured hash algorithm (e.g. TupleHash)
///
/// Unlike the algorithm as described by Renes and Smith, this implementation always produces a
/// proof scalar with an LSB of zero. [verify] checks for this, rejecting any signatures with a
/// proof scalar with an LSB of one. This eliminates malleability in the resulting signatures while
/// still producing signatures which are verifiable by standard implementations.
#[must_use]
pub fn sign(
    pk: &[u8; 32],
    sk: &[u8; 32],
    nonce: &[u8; 32],
    m: &[u8],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> [u8; 64] {
    let d = Scalar::clamp(sk);
    let k = Scalar::from_bytes_wide(&hash(&[nonce, m]));
    let i = &G * &k;
    let i = i.as_bytes();
    let r = Scalar::from_bytes_wide(&hash(&[&i, pk, m]));
    let s = hazmat::sign_challenge(&d, &k, &r);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&i);
    sig[32..].copy_from_slice(&s.as_bytes());
    sig
}

/// Verifies the signature given the public key and message.
///
/// * `pk`: the signer's public key
/// * `sig`: the signature produced by [sign]
/// * `m`: the message to be signed
/// * `hash`: a structured hash algorithm (e.g. TupleHash)
///
/// Unlike the algorithm as described by Renes and Smith, this implementation rejects any proof
/// scalar with an LSB of one. This eliminates malleability in the resulting signatures at the
/// expense of rejecting roughly half of valid signatures created by standard implementations.
#[must_use]
pub fn verify(
    pk: &[u8; 32],
    sig: &[u8; 64],
    m: &[u8],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> bool {
    let q = Point::from_bytes(pk);
    let i = Point::from_bytes(&sig[..32].try_into().unwrap());
    let s = Scalar::from_bytes(&sig[32..].try_into().unwrap());
    let r_p = Scalar::from_bytes_wide(&hash(&[&sig[..32], pk, m]));

    hazmat::verify_challenge(&q, &r_p, &i, &s)
}

/// Cryptographic functionality which will let you do stupid things to yourself.
pub mod hazmat {
    use super::*;

    /// Given the signer challenge `r` (e.g. `H(I || Q || m)`), returns the proof scalar `s`.
    ///
    /// Unlike [crate::hazmat::sign_challenge], only produces proof scalars with zero LSBs.
    #[must_use]
    pub fn sign_challenge(d: &Scalar, k: &Scalar, r: &Scalar) -> Scalar {
        crate::hazmat::sign_challenge(d, k, r).to_zero_lsb()
    }

    /// Verifies a counterfactual challenge, given a commitment point and proof scalar.
    ///
    /// * `q`: the signer's public key
    /// * `r_p`: the re-calculated challenge e.g. `r' = H(I' || Q' || m')`
    /// * `i`: the commitment point from the signature
    /// * `s`: the proof scalar from the signature
    ///
    /// Unlike [crate::hazmat::verify_challenge], only allows proof scalars with zero LSBs (i.e.
    /// [sign_challenge] output)..
    #[must_use]
    pub fn verify_challenge(q: &Point, r_p: &Scalar, i: &Point, s: &Scalar) -> bool {
        if (!s.is_zero_lsb()).into() {
            return false;
        }
        crate::hazmat::verify_challenge(q, r_p, i, s)
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rand::{thread_rng, Rng};

    use crate::qdsa::tests::shake128;
    use crate::x25519::public_key;

    use super::*;

    #[test]
    fn negate_proof_scalar() {
        let pk = hex!("a8bc0c539775462b2f21834ccddcb3c5d452b6702a85818bba5da1f0c2a90a59");
        let m = hex!("4f2b8a8027a8542bda6f");
        let mut sig = hex!(
            "8137f6865c2a5c74feb9f5a64ae06601ed0878d9bf6be8b8297221034e7bba64"
            "5a04f337ea101a11352ebb4c377e436b9502520a5e8056f5443ab15d2c25d10b"
        );

        assert!(crate::verify(&pk, &sig, &m, shake128));
        assert!(verify(&pk, &sig, &m, shake128));

        let s = Scalar::from_bytes(&sig[32..].try_into().expect("invalid scalar len"));
        sig[32..].copy_from_slice(&(-&s).as_bytes());

        assert!(crate::verify(&pk, &sig, &m, shake128));
        assert!(!verify(&pk, &sig, &m, shake128));
    }

    #[test]
    fn strict_round_trip() {
        for _ in 0..1000 {
            let sk_a = thread_rng().gen();
            let pk_a = public_key(&sk_a);
            let pk_b = public_key(&thread_rng().gen());
            let nonce = thread_rng().gen();

            let message = b"this is a message";

            let sig = sign(&pk_a, &sk_a, &nonce, message, shake128);
            let mut sig_p = sig;
            sig_p[4] ^= 1;

            assert!(verify(&pk_a, &sig, message, shake128));
            assert!(crate::verify(&pk_a, &sig, message, shake128));
            assert!(!verify(&pk_b, &sig, message, shake128));
            assert!(!verify(
                &pk_a,
                &sig,
                b"this is a different message",
                shake128
            ));
            assert!(!verify(&pk_a, &sig_p, message, shake128));
        }
    }
}
