//! A pure-Rust implementation of [qDSA](https://joostrenes.nl/publications/qdsa-eprint.pdf) (aka
//! Quotient DSA) over Curve25519. Includes X25519 key agreement, Elligator2 encoding and decoding,
//! and a designated-verifier adaptation of qDSA.
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
    pub use crate::qdsa::{
        dv_sign_challenge, dv_verify_challenge, sign_challenge, sign_commitment, verify_challenge,
    };
    pub use crate::scalar::Scalar;
}

/// Given a secret key `sk`, returns the corresponding public key.
pub fn public_key(sk: &[u8; 32]) -> [u8; 32] {
    let d = Scalar::clamp(sk);
    let q = &G * &d;
    q.as_bytes()
}
