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

    verify_challenge(&q, &r_p, &i, &s)
}

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
/// proof scalar with an LSB of zero. [verify_strict] checks for this, rejecting any signatures with
/// a proof scalar with an LSB of one. This eliminates malleability in the resulting signatures
/// while still producing signatures which are verifiable by standard implementations.
#[must_use]
pub fn sign_strict(
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
    let s = sign_challenge_strict(&d, &k, &r);

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
pub fn verify_strict(
    pk: &[u8; 32],
    sig: &[u8; 64],
    m: &[u8],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> bool {
    let q = Point::from_bytes(pk);
    let i = Point::from_bytes(&sig[..32].try_into().unwrap());
    let s = Scalar::from_bytes(&sig[32..].try_into().unwrap());
    let r_p = Scalar::from_bytes_wide(&hash(&[&sig[..32], pk, m]));

    verify_challenge_strict(&q, &r_p, &i, &s)
}

/// Given the signer challenge `r` (e.g. `H(I || Q || m)`), returns the proof scalar `s`.
#[must_use]
pub fn sign_challenge(d: &Scalar, k: &Scalar, r: &Scalar) -> Scalar {
    // If r has non-zero LSB, negate it to ensure it has a zero LSB.
    let r = (*r).to_zero_lsb();

    // Calculate and return the proof scalar.
    k - &(&r * d)
}

/// Given the signer challenge `r` (e.g. `H(I || Q || m)`), returns the proof scalar `s`.
///
/// Unlike [sign_challenge], only produces proof scalars with zero LSBs.
#[must_use]
pub fn sign_challenge_strict(d: &Scalar, k: &Scalar, r: &Scalar) -> Scalar {
    sign_challenge(d, k, r).to_zero_lsb()
}

/// Given a challenge (e.g. `H(I || Q_S || m)`), returns the designated proof point `x` using the
/// designated verifier's public key `q_v`.
///
/// This adapts
/// [Steinfeld, Wang, and Pieprzyk](https://www.iacr.org/archive/pkc2004/29470087/29470087.pdf)'s
/// designated verifier scheme for Schnorr signatures to Kummer varieties.
///
/// Use [dv_verify_challenge] to verify `i` and `x`.
#[must_use]
pub fn dv_sign_challenge(d_s: &Scalar, k: &Scalar, q_v: &Point, r: &Scalar) -> Point {
    q_v * &sign_challenge_strict(d_s, k, r)
}

/// Verifies a counterfactual challenge, given a commitment point and proof scalar.
///
/// * `q`: the signer's public key
/// * `r_p`: the re-calculated challenge e.g. `r' = H(I' || Q' || m')`
/// * `i`: the commitment point from the signature
/// * `s`: the proof scalar from the signature
#[must_use]
pub fn verify_challenge(q: &Point, r_p: &Scalar, i: &Point, s: &Scalar) -> bool {
    let t0 = &G * s; // t0 = [s]G = [k - rd]G
    let t1 = q * r_p; // t1 = [r]Q = [rd]G

    // return true iff ±[k]G ∈ {±([k - rd]G + [rd]G), ±([k - rd]G - [rd]G)}
    let (bzz, bxz, bxx) = b_values(&t0, &t1);
    check(&bzz, &bxz, &bxx, i)
}

/// Verifies a counterfactual challenge, given a commitment point and proof scalar.
///
/// * `q`: the signer's public key
/// * `r_p`: the re-calculated challenge e.g. `r' = H(I' || Q' || m')`
/// * `i`: the commitment point from the signature
/// * `s`: the proof scalar from the signature
///
/// Unlike [verify_challenge], only allows proof scalars with zero LSBs (i.e.
/// [sign_challenge_strict] output)..
#[must_use]
pub fn verify_challenge_strict(q: &Point, r_p: &Scalar, i: &Point, s: &Scalar) -> bool {
    if (!s.is_zero_lsb()).into() {
        return false;
    }
    verify_challenge(q, r_p, i, s)
}

/// Verifies a counterfactual challenge, given a commitment point and designated proof point.
///
/// * `q_s`: the signer's public key
/// * `d_v`: the designated verifier's private key
/// * `challenge`: the re-calculated challenge e.g. `H(I || Q_S || m)`
/// * `i`: the commitment point from the signature
/// * `x`: the designated proof point from the signature
#[must_use]
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
#[must_use]
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

    use crate::x25519::public_key;

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
        // generated with https://joostrenes.nl/software/cref-g1.tar.gz

        let pk = hex!("699cbdecf42280fcd5b41c0f48c67b81074a7560ace3f5cadd48e962eb65dd23");
        let nonce = hex!("bcf5164b2dfd7585c71d764af31aeb625159d40cd6717b279ff8d3e7c805e6f6");
        let sk = hex!("801a438d57b87ec80c0bbea7e8d638044039b1e7f906eacecf2a8711fd1f9b60");
        let m = hex!("dc701b0f388ffb91b020");
        let sig = hex!(
            "c62376dfa28d0a2bc4d134b5ec80dce4bcc0bd123579809c890dc46d83080470"
            "c0245d5891f6c4820da12d4159b7268126ce22456b95d8ca6d0edc55038ddb0e"
        );
        assert_eq!(sig, sign(&pk, &sk, &nonce, &m, shake128));
        assert!(verify(&pk, &sig, &m, shake128));

        let pk = hex!("366fb851a56023b3a21267b5894b85a969d30f41278fc2e2a78691315021b212");
        let nonce = hex!("44b0288da8bd3677f5b6863dfeaf921414e41a5ba57e7e309d1cf4ff8c562c5c");
        let sk = hex!("9896d8d382a2bf682568fc2e1020b5aa8f40272feb93b44c7dc33f5542ab3763");
        let m = hex!("e9c5f1b0c4158ae59b4d");
        let sig = hex!(
            "186728b271da40ae6954944cbb51d5eba299739b8276f0a2272220db3b5f7e2f"
            "5d5151c97e998496771ec634498946415ba6f3ac5d2af300cf959f6c99b09e0c"
        );
        assert_eq!(sig, sign(&pk, &sk, &nonce, &m, shake128));
        assert!(verify(&pk, &sig, &m, shake128));

        let pk = hex!("4143a10bb4f6f0892663ff88df1bb5e3beaa577067e5ea962f826c0f863e7713");
        let nonce = hex!("20267bbaf4d94eea029cf0377dd37eadff98d4bcc0f2c2f7b359e753a6499f86");
        let sk = hex!("30e1cb57fb3c06db1a0d30031ac466e5aed60ecac05fd3fac382c0a0a8259c52");
        let m = hex!("d38ae260892a15ca369b");
        let sig = hex!(
            "a613cf241e91172f11c7051792afd904042cc12bf6183d18564394b5b194e464"
            "f5fa65919338a7637ff2daa27a4c0ed8e49c2e68fab6b9e37a5f9ec30a5e4006"
        );
        assert_eq!(sig, sign(&pk, &sk, &nonce, &m, shake128));
        assert!(verify(&pk, &sig, &m, shake128));

        let pk = hex!("ce01b6c516c181c98a57c68aca7cb193714f0aec621ba82aa343be64dd8fcb40");
        let nonce = hex!("6af9deedbaa41e1e47ea8c71bf6c1d8da6eb3031b92e4f949dd556c02754a825");
        let sk = hex!("b808504a7cd0cc2879988a68c8c4adaa259a88ada8db92667bab9f02739ee842");
        let m = hex!("bd50d3104e3f9fb0d1e9");
        let sig = hex!(
            "fa826e1c1579d0cf91f8274156cd59071396a93dc730b93fa159f886fad33b67"
            "ac72c0b7eec24bd5dc4feb64073578215d9bbdbea0e69f22f206c9ab0449b506"
        );
        assert_eq!(sig, sign(&pk, &sk, &nonce, &m, shake128));
        assert!(verify(&pk, &sig, &m, shake128));

        let pk = hex!("daf5a3d2f08ef44385738b8c9d4a1b87efdbb79e5713b5dd49ae0b97ef8fdb14");
        let nonce = hex!("86d342615c5dfba1ee3165a0202252d179a5188ab3c04b8af15cca563d501239");
        let sk = hex!("001ce983c4b1aae4dbdb25365e543b4812add8fbb2b9471b56503d67d8c52878");
        let m = hex!("a715c5c013542a956d37");
        let sig = hex!(
            "34fcdce4ff4223815fb20abd27e350f5c88f1fcfdbc63b6ea36d7dbf85da9b04"
            "729973eb1912a06792ba54dcdfe926e4cd8c03c9c5d955d77a079f7db11b6908"
        );
        assert_eq!(sig, sign(&pk, &sk, &nonce, &m, shake128));
        assert!(verify(&pk, &sig, &m, shake128));

        let pk = hex!("cb8d1875438a48beeb2a7ccb0641db2f82ccdb99117d9fe51b57fe2630aaf252");
        let nonce = hex!("675bf669dc92c622ed055af8f8a5da036d49bd6090d5d7c9c3ed9193e0911773");
        let sk = hex!("989b4c30b91682a04e266ea8c12f0f8797d28d3bc489c7c9fcb13fa32422154b");
        let m = hex!("91dbb670d869b47a0885");
        let sig = hex!(
            "6ce32003734ada127f83c1638500a635602d0f2f2d127b80ae3d944d7fb1e84a"
            "1a3dc01746df15cf24d8709ae9690e19c4dd3fbee8833d0e3c0ba30957851002"
        );
        assert_eq!(sig, sign(&pk, &sk, &nonce, &m, shake128));
        assert!(verify(&pk, &sig, &m, shake128));

        let pk = hex!("a869b17d2fbe1fe27745586021201043ca54d8e943e36c60c46c45736f9c7706");
        let nonce = hex!("ba0d390b4d6bdffdd2cfa563aec4fddc29c2498044e14ac47385db496ad1197f");
        let sk = hex!("c8199feb6d092d1410a048be1a0ee2773eefa918b0d1700ae5a50dfbcbcb4457");
        let m = hex!("7ba0a7209d7e3f60a3d3");
        let sig = hex!(
            "ca60dc47dadb8c4367711617c3232a89f1263f11c92bae3b992530331175786d"
            "80b73b19c77c3e00b6cd4077db449609766a6c0ca46132b75bbf53126d28cb06"
        );
        assert_eq!(sig, sign(&pk, &sk, &nonce, &m, shake128));
        assert!(verify(&pk, &sig, &m, shake128));

        let pk = hex!("283e1bb0ac57d52342e08b0415f27d9fa54e8d3d90b727c424057243a1a00570");
        let nonce = hex!("91820ca5d1a28dd221940259bcce3bbb9eff97ad7d15ba488b737536377e8e9b");
        let sk = hex!("a83b16563667ae6213b40186c73f20714917c758272e2d78ef4232871bb47850");
        let m = hex!("656698d06293c9453e21");
        let sig = hex!(
            "b58ac2df98b671e1faf425f73de0918871ed7ec12d5ed4b5172344c1dca9f34c"
            "5c7cea06c262bd3f7f9a00364dbe2a260f7d05aee4a2fe4ce62a176f5d22a20c"
        );
        assert_eq!(sig, sign(&pk, &sk, &nonce, &m, shake128));
        assert!(verify(&pk, &sig, &m, shake128));

        let pk = hex!("a8bc0c539775462b2f21834ccddcb3c5d452b6702a85818bba5da1f0c2a90a59");
        let nonce = hex!("221e3ec71706d2568585249a6f6ef7aa8b3ddcf63ffe20560875e2de07668cd3");
        let sk = hex!("a012a86000174e1c3ff635307874bfbc9ae67371f78186ceb58b7df68d4bd25e");
        let m = hex!("4f2b8a8027a8542bda6f");
        let sig = hex!(
            "8137f6865c2a5c74feb9f5a64ae06601ed0878d9bf6be8b8297221034e7bba64"
            "5a04f337ea101a11352ebb4c377e436b9502520a5e8056f5443ab15d2c25d10b"
        );
        assert_eq!(sig, sign(&pk, &sk, &nonce, &m, shake128));
        assert!(verify(&pk, &sig, &m, shake128));

        let pk = hex!("9084b27fddbaac28c094a2423cfb0dc8392c26d606c3e1ec078d463426e79c20");
        let nonce = hex!("e99b3e4874b2669141f3bd44fc0f52ade4e6f320bf368c111a9c1be558a1f5cb");
        let sk = hex!("9078bb54125a6505b49afba6eca02a2ca3bb18009c42d7de870a9110a9d14f52");
        let m = hex!("39f17b30ecbdde1075bd");
        let sig = hex!(
            "2f515d842513526f6a6b8d0b0f0643121bf4f598a08267404d332748579c1049"
            "09cb8495f9c7f3846012048ac367417e2a2435e7419eb588d98727d070db3f05"
        );
        assert_eq!(sig, sign(&pk, &sk, &nonce, &m, shake128));
        assert!(verify(&pk, &sig, &m, shake128));
    }

    #[test]
    fn negate_proof_scalar() {
        let pk = hex!("a8bc0c539775462b2f21834ccddcb3c5d452b6702a85818bba5da1f0c2a90a59");
        let m = hex!("4f2b8a8027a8542bda6f");
        let mut sig = hex!(
            "8137f6865c2a5c74feb9f5a64ae06601ed0878d9bf6be8b8297221034e7bba64"
            "5a04f337ea101a11352ebb4c377e436b9502520a5e8056f5443ab15d2c25d10b"
        );

        assert!(verify(&pk, &sig, &m, shake128));
        assert!(verify_strict(&pk, &sig, &m, shake128));

        let s = Scalar::from_bytes(&sig[32..].try_into().expect("invalid scalar len"));
        sig[32..].copy_from_slice(&(-&s).as_bytes());

        assert!(verify(&pk, &sig, &m, shake128));
        assert!(!verify_strict(&pk, &sig, &m, shake128));
    }

    #[test]
    fn modified_commitment_point() {
        let pk = hex!("a8bc0c539775462b2f21834ccddcb3c5d452b6702a85818bba5da1f0c2a90a59");
        let m = hex!("4f2b8a8027a8542bda6f");
        let mut sig = hex!(
            "8137f6865c2a5c74feb9f5a64ae06601ed0878d9bf6be8b8297221034e7bba64"
            "5a04f337ea101a11352ebb4c377e436b9502520a5e8056f5443ab15d2c25d10b"
        );

        assert!(verify(&pk, &sig, &m, shake128));

        // flip the unused bit
        sig[31] ^= 0b1000_0000;

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
    fn strict_round_trip() {
        for _ in 0..1000 {
            let sk_a = thread_rng().gen();
            let pk_a = public_key(&sk_a);
            let pk_b = public_key(&thread_rng().gen());
            let nonce = thread_rng().gen();

            let message = b"this is a message";

            let sig = sign_strict(&pk_a, &sk_a, &nonce, message, shake128);
            let mut sig_p = sig;
            sig_p[4] ^= 1;

            assert!(verify_strict(&pk_a, &sig, message, shake128));
            assert!(verify(&pk_a, &sig, message, shake128));
            assert!(!verify_strict(&pk_b, &sig, message, shake128));
            assert!(!verify_strict(
                &pk_a,
                &sig,
                b"this is a different message",
                shake128
            ));
            assert!(!verify_strict(&pk_a, &sig_p, message, shake128));
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
