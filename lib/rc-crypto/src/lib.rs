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

mod cached_string_repr;
pub mod certificate;
mod hex;
pub mod issuer;
pub mod keys;
mod signature;
mod signer;

pub use signature::*;
pub use signer::*;
