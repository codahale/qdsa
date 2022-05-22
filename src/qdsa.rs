use crate::point::{Point, G};
use crate::scalar::Scalar;

/// Signs the message using the given key pair, nonce, and hash function.
pub fn sign(
    pk: &[u8; 32],
    sk: &[u8; 32],
    nonce: &[u8; 32],
    m: &[u8],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> [u8; 64] {
    let d = Scalar::clamp(sk);

    let k = Scalar::wide_reduce(&hash(&[nonce, m]));
    let i = (&G * &k).as_bytes();

    let r = Scalar::wide_reduce(&hash(&[&i, pk, m])).abs();
    let s = (&k - &(&r * &d)).abs();

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&i);
    sig[32..].copy_from_slice(&s.as_bytes());
    sig
}

/// Verifies the signature given the public key and message.
pub fn verify(
    pk: &[u8; 32],
    sig: &[u8; 64],
    m: &[u8],
    mut hash: impl FnMut(&[&[u8]]) -> [u8; 64],
) -> bool {
    let q = Point::from_bytes(pk);

    let i = Point::from_bytes(&sig[..32].try_into().unwrap());
    let s = Scalar::reduce(&sig[32..].try_into().unwrap());
    if !s.is_pos() {
        return false;
    }

    let r_p = Scalar::wide_reduce(&hash(&[&sig[..32], pk, m]));

    verify_detached(&q, &r_p, &i, &s)
}

/// Verifies the detached components of a signature:
///
/// * `q`: the signer's public key
/// * `r_p`: the re-calculated challenge scalar `H(i || q || m)`
/// * `i`: the commitment point from the signature
/// * `s`: the proof scalar from the signature
pub fn verify_detached(q: &Point, r_p: &Scalar, i: &Point, s: &Scalar) -> bool {
    let t0 = &G * s;
    let t1 = q * r_p;

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
        let sig = hex!("8137f6865c2a5c74feb9f5a64ae06601ed0878d9bf6be8b8297221034e7bba645a04f337ea101a11352ebb4c377e436b9502520a5e8056f5443ab15d2c25d10b");
        let sig_a = sign(&pk, &sk, &nonce, &m, shake128);
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
}
