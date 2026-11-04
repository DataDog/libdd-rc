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

use crate::test_issuer::{
    CertBuilder, ChainMutator, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

/// The dNSName SAN placed on the leaf, which does not match the
/// `EndpointHostname` the chain is verified against.
pub(crate) const MISMATCHED_LEAF_SAN: &str = "wrong.itsallbroken.com";

/// Produces a [`TestChain`] whose leaf carries a dNSName SAN that does not
/// match the `EndpointHostname` presented at verification time.
///
/// The chain is cryptographically valid, but must be rejected because the DC
/// pin does not hold - the connected DC is not permitted to sign payloads for
/// the requested hostname.
///
/// # Name Constraints
///
/// This mutator also clears the permitted dNSName constraints that
/// [`TestChain::build`] places on every intermediate. Those constraints are
/// evaluated while building the path, which happens strictly before the leaf
/// SAN is matched against the `EndpointHostname`; leaving them in place would
/// cause the chain to be rejected as a name constraint violation instead, and
/// the leaf SAN check would never run.
#[derive(Debug, Clone, Default)]
pub(crate) struct MismatchedLeafSan {}

impl ChainMutator for MismatchedLeafSan {
    fn intermediate<'a>(
        &self,
        builder: &mut CertBuilder<IntermediateTemplate<'a>>,
        _index: u8,
        _total: u8,
    ) {
        builder.set_allowed_domains(vec![]);
    }

    fn leaf<'a>(&self, builder: &mut CertBuilder<LeafTemplate<'a>>) {
        builder.with_sans([MISMATCHED_LEAF_SAN]);
    }

    fn complete(&self, chain: TestChain) -> TestChain {
        chain
    }
}
