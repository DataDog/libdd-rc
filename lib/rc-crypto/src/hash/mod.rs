//! Cryptographic hash algorithms.
//!
//! You should strongly prefer creating domain-specific type wrappers over raw
//! [`Digest`] to provide type safety.

mod digest;
mod sha256;

pub use digest::*;
pub use sha256::*;
