//! Payload verification using a trust store of verified [`Certificate`].
//!
//! [`Certificate`]: rc_crypto::certificate::Certificate

mod cache;
mod traits;

pub use cache::*;
pub use traits::*;
