#![doc = include_str!("../README.md")]
#![allow(
    clippy::field_reassign_with_default, // Default values, plus a field override.
    clippy::default_constructed_unit_structs // Unit structs do not appear as values.
)]
#![warn(
    missing_docs,
    missing_debug_implementations, // Frequently used bound on data structures
    unreachable_pub, // Visibility is part of communicating with humans
    unused_crate_dependencies, // Warn for unused dependencies
    clippy::clone_on_ref_ptr, // A ref +1 is not the same as a deep copy
    clippy::future_not_send, // Required for multithreaded runtimes
    clippy::dbg_macro, // Used for debugging, should not be in committed code
    clippy::todo, // Should not be in committed code - use unreachable!("reason")
)]

// False-positive lint for dev dependencies.
#[cfg(test)]
use criterion as _;

// Test only code.
#[cfg(test)]
mod valuable_assert;

pub mod certificate;
mod hex;
pub mod issuer;
pub mod keys;
mod signature;
mod signer;

pub use signature::*;
pub use signer::*;
