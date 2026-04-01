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

#![doc = "../README.md"]
// Nothing is used yet.
#![allow(unused)]

mod abort_on_drop;
pub(crate) mod codec;
pub(crate) mod connection;
pub(crate) mod entrypoint;
mod shutdown_signal;
mod test_harness;
pub(crate) use abort_on_drop::*;
pub(crate) use shutdown_signal::*;

pub mod host_runtime;
pub(crate) mod payload;

#[cfg(feature = "_test_harness")]
pub mod non_public_do_not_use {
    //! An external / pub interface to internal testing harness code.
    //!
    //! This module exists only when the `_test_harness` feature is enabled, and
    //! should not be used outside of tests / benchmarks / etc.
    pub use crate::test_harness::*;
}
