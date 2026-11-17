// Copyright 2026-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
