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

//! Internal trust chain building, and chain validation logic.
#![allow(clippy::module_inception)]

mod build_unverified;
mod unverified;
mod verify_chain;

pub use build_unverified::*;
pub(crate) use unverified::*;

#[allow(dead_code, unused_imports)]
pub(crate) use verify_chain::*;

/// These property test input generator functions are used to classify attacks
/// and document at which stage they fail during processing. Either:
///
///   * Chain building (using SKI / AKI values).
///   * Chain verification (using cryptographic signatures and constrain
///     checks).
///
#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use crate::test_issuer::{
        ExpiredIntermediate, ExpiredLeaf, ForgedIntermediate, ForgedLeaf, FutureValidIntermediate,
        FutureValidLeaf, MissingIntermediate, PathLenViolation, TestCA, TestChain, arbitrary_chain,
    };

    /// A set of chain mutations that result in an invalid chain being produced,
    /// which is not detected as invalid by [`build_unverified_chain_for()`] and
    /// returned to the caller (needing further verification).
    ///
    /// [`build_unverified_chain_for()`]: super::build_unverified_chain_for
    pub(crate) fn arbitrary_invalid_chain_spuriously_built(
        ca: &'static TestCA,
        n_intermediates: impl Strategy<Value = u8> + Clone + 'static,
    ) -> impl Strategy<Value = TestChain> {
        prop_oneof![
            arbitrary_chain(ca, n_intermediates.clone(), ForgedLeaf::default()),
            arbitrary_chain(ca, n_intermediates.clone(), PathLenViolation::default()),
            arbitrary_chain(ca, n_intermediates.clone(), ExpiredLeaf::default()),
            arbitrary_chain(ca, n_intermediates.clone(), FutureValidLeaf::default()),
            n_intermediates
                .clone()
                .prop_flat_map(|n| any::<u8>().prop_map(move |seed| (n, seed)))
                .prop_map(move |(n, seed)| TestChain::build(ca, n, ForgedIntermediate::new(seed))),
            n_intermediates
                .clone()
                .prop_flat_map(|n| any::<u8>().prop_map(move |seed| (n, seed)))
                .prop_map(move |(n, seed)| TestChain::build(ca, n, ExpiredIntermediate::new(seed))),
            n_intermediates
                .prop_flat_map(|n| any::<u8>().prop_map(move |seed| (n, seed)))
                .prop_map(move |(n, seed)| TestChain::build(
                    ca,
                    n,
                    FutureValidIntermediate::new(seed),
                )),
        ]
    }

    /// The set of chain mutations which MUST be detected as resulting in an
    /// invalid chain at some point during chain processing.
    ///
    /// This set covers all mutations that result in an invalid chain, and is a
    /// strict superset of [`arbitrary_invalid_chain_spuriously_built()`].
    pub(crate) fn arbitrary_invalid_chain(
        ca: &'static TestCA,
        n_intermediates: impl Strategy<Value = u8> + Clone + 'static,
    ) -> impl Strategy<Value = TestChain> {
        prop_oneof![
            // All the inputs that result in an UntrustedChain being constructed
            // from an invalid input chain.
            arbitrary_invalid_chain_spuriously_built(ca, n_intermediates.clone()),
            // Plus test cases that are not spuriously accepted during chain
            // building, but MUST be rejected either during chain building or
            // verification.
            n_intermediates
                .clone()
                .prop_flat_map(|n| any::<u8>().prop_map(move |seed| (n, seed)))
                .prop_map(move |(n, seed)| TestChain::build(ca, n, MissingIntermediate::new(seed))),
        ]
    }
}
