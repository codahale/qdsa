//! qdsa provides a small, portable implementation of the
//! [qDSA](https://joostrenes.nl/publications/qdsa-eprint.pdf) digital signature algorithm
//! instantiated with the Curve25519 elliptic curve, plus the X25519 key agreement algorithm.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub use crate::qdsa::{keypair, sign, verify};
pub use crate::x25519::{dh_keygen, x25519};

mod fe25519;
mod point;
mod qdsa;
mod scalar;
mod x25519;
