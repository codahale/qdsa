//! Elligator2 maps Curve25519 public keys to uniform bitstrings and back.

use rand_core::{CryptoRng, RngCore};

use crate::hazmat::Point;

/// Converts public key `pk` to an Elligator2 representative, if possible. Uses `rng` to mask the
/// constant bits of the resulting Curve25519 field element. Not all public keys map to
/// representatives.
pub fn public_key_to_representative(
    pk: &[u8; 32],
    mut rng: impl RngCore + CryptoRng,
) -> Option<[u8; 32]> {
    let mut mask = [0u8; 1];
    rng.fill_bytes(&mut mask);

    Point::from_bytes(pk).to_elligator(mask[0])
}

/// Converts Elligator2 representative `rep` to a Curve25519 public key. All possible
/// representatives map to public keys.
pub fn representative_to_public_key(rep: &[u8; 32]) -> [u8; 32] {
    Point::from_elligator(rep).as_bytes()
}

/// Generates a random secret key, public key, and Elligator2 representative.
pub fn key_pair(mut rng: impl RngCore + CryptoRng) -> ([u8; 32], [u8; 32], [u8; 32]) {
    loop {
        // Generate a secret key.
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);

        // Calculate the public key.
        let pk = crate::public_key(&sk);

        // Try to calculate the representative.
        if let Some(rep) = public_key_to_representative(&pk, &mut rng) {
            return (sk, pk, rep);
        }
    }
}
