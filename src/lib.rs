//! A pure-Rust implementation of [qDSA](https://joostrenes.nl/publications/qdsa-eprint.pdf) (aka
//! Quotient DSA) over Curve25519. Includes X25519 key agreement, Elligator2 encoding and decoding,
//! and a designated-verifier adaptation of qDSA.
#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::missing_const_for_fn)]

pub use crate::qdsa::{sign, sign_strict, verify, verify_strict};

mod point;
mod qdsa;
mod scalar;
pub mod x25519;

/// Cryptographic functionality which will let you do stupid things to yourself.
pub mod hazmat {
    pub use crate::point::{Point, G};
    pub use crate::qdsa::{
        dv_sign_challenge, dv_verify_challenge, sign_challenge, sign_challenge_strict,
        verify_challenge, verify_challenge_strict,
    };
    pub use crate::scalar::Scalar;
}
