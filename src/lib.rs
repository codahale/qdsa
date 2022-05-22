//! qdsa provides a small, portable implementation of the
//! [qDSA](https://joostrenes.nl/publications/qdsa-eprint.pdf) digital signature algorithm
//! instantiated with the Curve25519 elliptic curve, plus the X25519 key agreement algorithm.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use crate::point::G;
pub use crate::qdsa::{sign, verify};
use crate::scalar::Scalar;
pub use crate::x25519::x25519;

mod point;
mod qdsa;
mod scalar;
mod x25519;

/// Cryptographic functionality which will let you do stupid things to yourself.
pub mod hazmat {
    pub use crate::point::{Point, G};
    pub use crate::qdsa::verify_detached;
    pub use crate::scalar::Scalar;
}

/// Given a secret key `sk`, returns the corresponding public key.
pub fn public_key(sk: &[u8; 32]) -> [u8; 32] {
    let d = Scalar::clamp(sk);
    let q = &G * &d;
    q.as_bytes()
}
