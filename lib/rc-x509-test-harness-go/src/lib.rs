//! Test harness for Go FFI tests.
//!
//! This crate re-export all FFI functions from rc-x509-ffi
//! and provide test-specific functionality.

#![allow(unsafe_code)]

// Re-export everything from rc-x509-ffi
pub use rc_x509_ffi::*;
