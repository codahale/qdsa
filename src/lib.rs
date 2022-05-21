//! qdsa provides a small, portable implementation of the
//! [qDSA](https://joostrenes.nl/publications/qdsa-eprint.pdf) digital signature algorithm
//! instantiated with the Curve25519 elliptic curve, plus the X25519 key agreement algorithm.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub use crate::qdsa::{sign, verify};
use crate::scalar::Scalar;
pub use crate::x25519::x25519;

mod fe25519;
mod point;
mod qdsa;
mod scalar;
mod x25519;

/// Given a secret key `sk`, returns the corresponding public key.
pub fn public_key(sk: &[u8; 32]) -> [u8; 32] {
    let d = Scalar::clamp(sk);
    let q = point::ladder_base(&d);
    q.as_bytes()
}
