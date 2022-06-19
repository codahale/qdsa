//! An adaptation of
//! [Steinfeld, Wang, and Pieprzyk](https://www.iacr.org/archive/pkc2004/29470087/29470087.pdf)'s
//! designated verifier scheme for Schnorr signatures to Kummer varieties over Curve25519.
//!
//! This produces digital signatures which can only be verified by the owner of a given public key.
//! The only way the verifier can convince a third party of the validity of a designated signature
//! is to reveal their own private key.
use crate::hazmat::{Point, Scalar, G};

/// Signs a message with the designated verifier qDSA algorithm.
///
/// In the formal description of the algorithm, a 32-byte secret key is hashed into a 64-byte value:
///
/// ```text
/// d' || d'' = H(k)
/// ```
///
/// For this API, `sk = d'`, `pk = [d']G`, and `nonce = d''`.
///
/// * `vk`: the verifier's public key
/// * `sk`: the signer's secret key (i.e. `d''` in the literature)
/// * `nonce`: a pseudorandom secret value (i.e. `d'` in the literature)
/// * `m`: the message to be signed
/// * `hash`: a structured hash algorithm (e.g. TupleHash)
#[must_use]
pub fn sign(
    vk: &[u8; 32],
    sk: &[u8; 32],
    nonce: &[u8; 32],
    m: &[u8],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> [u8; 64] {
    let q_v = Point::from_bytes(vk);
    let d = Scalar::clamp(sk);
    let q = &G * &d;
    let k = Scalar::from_bytes_wide(&hash(&[nonce, m]));
    let i = &G * &k;
    let i = i.as_bytes();
    let r = Scalar::from_bytes_wide(&hash(&[&i, &q.as_bytes(), m]));
    let x = hazmat::sign_challenge(&d, &k, &q_v, &r);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&i);
    sig[32..].copy_from_slice(&x.as_bytes());
    sig
}

/// Verifies the signature given the verifier's secret key, the signer's public key, and the message.
///
/// * `sk`: the verifier's secret key
/// * `pk`: the signer's public key
/// * `sig`: the signature produced by [sign]
/// * `m`: the message to be signed
/// * `hash`: a structured hash algorithm (e.g. TupleHash)
#[must_use]
pub fn verify(
    sk: &[u8; 32],
    pk: &[u8; 32],
    sig: &[u8; 64],
    m: &[u8],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> bool {
    let d = Scalar::clamp(sk);
    let q = Point::from_bytes(pk);
    let i = Point::from_bytes(&sig[..32].try_into().unwrap());
    let x = Point::from_bytes(&sig[32..].try_into().unwrap());
    let r_p = Scalar::from_bytes_wide(&hash(&[&sig[..32], pk, m]));

    hazmat::verify_challenge(&q, &d, &r_p, &i, &x)
}

/// Cryptographic functionality which will let you do stupid things to yourself.
pub mod hazmat {
    use super::*;

    /// Given a challenge (e.g. `H(I || Q_S || m)`), returns the designated proof point `x` using the
    /// designated verifier's public key `q_v`.
    ///
    /// Use [verify_challenge] to verify `i` and `x`.
    #[must_use]
    pub fn sign_challenge(d_s: &Scalar, k: &Scalar, q_v: &Point, r: &Scalar) -> Point {
        q_v * &crate::strict::hazmat::sign_challenge(d_s, k, r)
    }

    /// Verifies a counterfactual challenge, given a commitment point and designated proof point.
    ///
    /// * `q_s`: the signer's public key
    /// * `d_v`: the designated verifier's private key
    /// * `challenge`: the re-calculated challenge e.g. `H(I || Q_S || m)`
    /// * `i`: the commitment point from the signature
    /// * `x`: the designated proof point from the signature
    #[must_use]
    pub fn verify_challenge(q_s: &Point, d_v: &Scalar, r_p: &Scalar, i: &Point, x: &Point) -> bool {
        let t0 = x * &d_v.invert(); // t0 = [1/d_V]X = [((k - rd_S)d_V)(1/d_V)]G
        let t1 = q_s * r_p; // t1 = [r]Q = [rd_S]G

        // return true iff ±[k]G ∈ {±([k - rd_S]G + [rd_S]G), ±([k - rd_S]G - [rd_S]G)}
        i.equal_up_to_sign(&t0, &t1).into()
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use crate::public_key;
    use crate::tests::shake128;

    use super::*;

    #[test]
    fn round_trip() {
        for _ in 0..1000 {
            let sk_a = thread_rng().gen();
            let pk_a = public_key(&sk_a);
            let sk_b = thread_rng().gen();
            let pk_b = public_key(&sk_b);
            let nonce = thread_rng().gen();

            let message = b"this is a message";

            let sig = sign(&pk_b, &sk_a, &nonce, message, shake128);
            let mut sig_p = sig;
            sig_p[4] ^= 1;

            assert!(verify(&sk_b, &pk_a, &sig, message, shake128));
            assert!(!verify(&sk_a, &pk_a, &sig, message, shake128));
            assert!(!verify(&sk_b, &pk_b, &sig, message, shake128));
            assert!(!verify(
                &sk_b,
                &pk_a,
                &sig,
                b"this is a different message",
                shake128,
            ));
            assert!(!verify(&sk_b, &pk_a, &sig_p, message, shake128));
        }
    }
}
