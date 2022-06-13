//! Elligator 2 maps Curve25519 points to uniform bitstrings and back.

use rand_core::{CryptoRng, RngCore};

use crate::hazmat::Point;

/// Converts public key `pk` to an Elligator2 representative, if possible. Uses `rng` to mask the
/// constant bits of the resulting Curve25519 field element. Not all points map to representatives.
pub fn point_to_representative(
    pk: &[u8; 32],
    mut rng: impl RngCore + CryptoRng,
) -> Option<[u8; 32]> {
    let mut mask = [0u8; 1];
    rng.fill_bytes(&mut mask);

    Point::from_bytes(pk).to_elligator(mask[0])
}

/// Converts Elligator2 representative `rep` to a Curve25519 public key. All possible
/// representatives map to points.
pub fn representative_to_point(rep: &[u8; 32]) -> [u8; 32] {
    Point::from_elligator(rep).as_bytes()
}
