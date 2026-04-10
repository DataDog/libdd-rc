//! Code to establish trust between [`Certificate`].
//!
//! [`Certificate`]: rc_crypto::certificate::Certificate

#![allow(dead_code)]

mod untrusted_cert;

pub use untrusted_cert::*;
