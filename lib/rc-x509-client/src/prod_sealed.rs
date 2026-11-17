#![allow(unreachable_pub)]

//! This module contains a build-time switch, that prevents external
//! implementations of critical code in release builds, while allowing
//! flexibility for test harnesses.
//!
//! In release (production) builds, this [`ProdSealed`] cannot be implemented by
//! external crates, and nor can any super-traits that depend on it ("sealing"
//! those traits).
//!
//! In debug builds, [`ProdSealed`] can be implemented by external crates.

cfg_select! {
    debug_assertions => {
        /// A trait that can only be `impl` in debug builds.
        pub trait ProdSealed {}
    }
    _ => {

        /// A trait that can only be `impl` in debug builds.
        pub(crate) trait ProdSealed {}
    }
}
