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

//! A test certificate issuer: root CAs, certificate builders, and the valid /
//! adversarial certificate chains issued by them.
//!
//! Each [`TestCA`] mints its own random root of trust, so a caller can scope a
//! trust anchor to a single test.

// Callers use a subset of this API surface, and it is test-only helper code.
#![allow(dead_code, missing_docs)]

mod ca;
mod cert_builder;
mod chain_builder;
mod identity;

#[allow(unused_imports)]
pub use ca::*;
pub use cert_builder::*;
pub use chain_builder::*;
pub use identity::*;
