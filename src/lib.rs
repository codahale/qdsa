#![cfg_attr(not(feature = "std"), no_std)]

pub use sign::{keypair, sign, verify};
pub use x25519::{dh_exchange, dh_keygen};

mod fe25519;
mod point;
mod scalar;
mod sign;
mod x25519;
