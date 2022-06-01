use crate::point::{Point, G};
use crate::scalar::Scalar;

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
    let s = sign_challenge(&d, &k, &r);

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

    verify_challenge(&q, &r_p, &i, &s)
}

/// Given the signer challenge `r` (e.g. `H(I || Q || m)`), returns the proof scalar `s`.
pub fn sign_challenge(d: &Scalar, k: &Scalar, r: &Scalar) -> Scalar {
    (k - &(r * d)).abs()
}

/// Given a challenge (e.g. `H(I || Q_S || m)`), returns the designated proof point `x` using the
/// designated verifier's public key `q_v`.
///
/// This adapts
/// [Steinfeld, Wang, and Pieprzyk](https://www.iacr.org/archive/pkc2004/29470087/29470087.pdf)'s
/// designated verifier scheme for Schnorr signatures to Kummer varieties.
///
/// Use [dv_verify_challenge] to verify `i` and `x`.
pub fn dv_sign_challenge(d_s: &Scalar, k: &Scalar, q_v: &Point, r: &Scalar) -> Point {
    q_v * &sign_challenge(d_s, k, r)
}

/// Verifies a counterfactual challenge, given a commitment point and proof scalar.
///
/// * `q`: the signer's public key
/// * `r_p`: the re-calculated challenge e.g. `r' = H(I' || Q' || m')`
/// * `i`: the commitment point from the signature
/// * `s`: the proof scalar from the signature
pub fn verify_challenge(q: &Point, r_p: &Scalar, i: &Point, s: &Scalar) -> bool {
    // Disallow negative proof scalars. We never produce negative proof scalars, and allowing
    // negative values here allows for malleable signatures.
    if !s.is_pos() {
        return false;
    }

    let t0 = &G * s; // t0 = [s]G = [k - rd]G
    let t1 = q * r_p; // t1 = [r]Q = [rd]G

    // return true iff ±[k]G ∈ {±([k - rd]G + [rd]G), ±([k - rd]G - [rd]G)}
    let (bzz, bxz, bxx) = b_values(&t0, &t1);
    check(&bzz, &bxz, &bxx, i)
}

/// Verifies a counterfactual challenge, given a commitment point and designated proof point.
///
/// * `q_s`: the signer's public key
/// * `d_v`: the designated verifier's private key
/// * `challenge`: the re-calculated challenge e.g. `H(I || Q_S || m)`
/// * `i`: the commitment point from the signature
/// * `x`: the designatued proof point from the signature
pub fn dv_verify_challenge(q_s: &Point, d_v: &Scalar, r_p: &Scalar, i: &Point, x: &Point) -> bool {
    let t0 = x * &d_v.invert(); // t0 = [1/d_V]X = [((k - rd_S)d_V)(1/d_V)]G
    let t1 = q_s * r_p; // t1 = [r]Q = [rd_S]G

    // return true iff ±[k]G ∈ {±([k - rd_S]G + [rd_S]G), ±([k - rd_S]G - [rd_S]G)}
    let (bzz, bxz, bxx) = b_values(&t0, &t1);
    check(&bzz, &bxz, &bxx, i)
}

// Return `true` iff `B_XX(i)^2 - B_XZ(i) + B_ZZ = 0`.
#[must_use]
fn check(bzz: &Point, bxz: &Point, bxx: &Point, i: &Point) -> bool {
    (&(&(bxx * &i.square()) - &(bxz * i)) + bzz)
        .is_zero()
        .into()
}

// Return the three biquadratic forms B_XX, B_XZ and B_ZZ in the coordinates of t0 and t1.
fn b_values(t0: &Point, t1: &Point) -> (Point, Point, Point) {
    let b0 = t0 * t1;
    let bzz = (&b0 - &Point::ONE).square();

    let bxz = t0 + t1;
    let bxz = &bxz * &(&b0 + &Point::ONE);
    let b0 = t0 * t1;
    let b0 = &b0 + &b0;
    let b0 = &b0 + &b0;
    let b1 = &b0 + &b0;
    let bxz = &bxz + &(&b1.mul121666() - &b0);
    let bxz = &bxz + &bxz;

    let bxx = (t0 - t1).square();

    (bzz, bxz, bxx)
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
        let sig = hex!(
            "8137f6865c2a5c74feb9f5a64ae06601ed0878d9bf6be8b8297221034e7bba64"
            "5a04f337ea101a11352ebb4c377e436b9502520a5e8056f5443ab15d2c25d10b"
        );
        let sig_a = sign(&pk, &sk, &nonce, &m, shake128);
        assert_eq!(sig, sig_a);
        assert!(verify(&pk, &sig, &m, shake128));
    }

    #[test]
    fn negative_proof_scalar() {
        let pk = hex!("a8bc0c539775462b2f21834ccddcb3c5d452b6702a85818bba5da1f0c2a90a59");
        let m = hex!("4f2b8a8027a8542bda6f");
        let mut sig = hex!(
            "8137f6865c2a5c74feb9f5a64ae06601ed0878d9bf6be8b8297221034e7bba64"
            "5a04f337ea101a11352ebb4c377e436b9502520a5e8056f5443ab15d2c25d10b"
        );

        let s = Scalar::from_bytes(&sig[32..].try_into().expect("invalid scalar len"));
        sig[32..].copy_from_slice(&(-&s).as_bytes());

        assert!(!verify(&pk, &sig, &m, shake128));
    }

    #[test]
    fn negative_commitment_point() {
        let pk = hex!("a8bc0c539775462b2f21834ccddcb3c5d452b6702a85818bba5da1f0c2a90a59");
        let m = hex!("4f2b8a8027a8542bda6f");
        let mut sig = hex!(
            "8137f6865c2a5c74feb9f5a64ae06601ed0878d9bf6be8b8297221034e7bba64"
            "5a04f337ea101a11352ebb4c377e436b9502520a5e8056f5443ab15d2c25d10b"
        );

        let i = Point::from_bytes(&sig[..32].try_into().expect("invalid point len"));
        sig[..32].copy_from_slice(&(-&i).as_bytes());

        assert!(!verify(&pk, &sig, &m, shake128));
    }

    #[test]
    fn sig_bit_flip() {
        let pk = hex!("a8bc0c539775462b2f21834ccddcb3c5d452b6702a85818bba5da1f0c2a90a59");
        let m = hex!("4f2b8a8027a8542bda6f");
        let sig = hex!(
            "8137f6865c2a5c74feb9f5a64ae06601ed0878d9bf6be8b8297221034e7bba64"
            "5a04f337ea101a11352ebb4c377e436b9502520a5e8056f5443ab15d2c25d10b"
        );
        assert!(verify(&pk, &sig, &m, shake128));

        for i in 0..sig.len() {
            for j in 0u8..8 {
                let mut sig_p = sig;
                sig_p[i] ^= 1 << j;

                assert!(
                    !verify(&pk, &sig_p, &m, shake128),
                    "bit flip at byte {}, bit {} produced a valid message",
                    i,
                    j
                );
            }
        }
    }

    #[test]
    fn qdsa_round_trip() {
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

    #[test]
    fn dv_qdsa_round_trip() {
        for _ in 0..1000 {
            let d_s = Scalar::clamp(&thread_rng().gen());
            let q_s = &G * &d_s;

            let d_v = Scalar::clamp(&thread_rng().gen());
            let q_v = &G * &d_v;

            let message = b"this is a message";

            // Create a designated verifier signature.
            let (i, x) = {
                // Generate a standard commitment.
                let nonce = thread_rng().gen::<[u8; 32]>();
                let k = Scalar::from_bytes_wide(&shake128(&[&nonce, &d_s.as_bytes(), message]));
                let i = &G * &k;
                let r =
                    Scalar::from_bytes_wide(&shake128(&[&i.as_bytes(), &q_s.as_bytes(), message]));
                let x = dv_sign_challenge(&d_s, &k, &q_v, &r);
                (i, x)
            };

            // Re-create the challenge using the commitment point.
            let r_p =
                Scalar::from_bytes_wide(&shake128(&[&i.as_bytes(), &q_s.as_bytes(), message]));
            assert!(dv_verify_challenge(&q_s, &d_v, &r_p, &i, &x));
        }
    }
}
