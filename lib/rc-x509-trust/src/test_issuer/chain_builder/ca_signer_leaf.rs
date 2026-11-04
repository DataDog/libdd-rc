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

use rcgen::{BasicConstraints, IsCa};

use crate::test_issuer::{
    CertBuilder, ChainMutator, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

/// Produces a [`TestChain`] whose leaf signer certificate asserts `CA:TRUE`.
///
/// The chain is cryptographically valid, but must be rejected during
/// verification: a certificate that is permitted to issue other certificates
/// must not also be used to sign payloads, as doing so would let the holder
/// mint a signer for any identity the CA is trusted for.
#[derive(Debug, Clone, Default)]
pub(crate) struct CaSignerLeaf {}

impl ChainMutator for CaSignerLeaf {
    fn intermediate<'a>(
        &self,
        _builder: &mut CertBuilder<IntermediateTemplate<'a>>,
        _index: u8,
        _total: u8,
    ) {
    }

    fn leaf<'a>(&self, builder: &mut CertBuilder<LeafTemplate<'a>>) {
        builder.set_is_ca(IsCa::Ca(BasicConstraints::Unconstrained));
    }

    fn complete(&self, chain: TestChain) -> TestChain {
        chain
    }
}
