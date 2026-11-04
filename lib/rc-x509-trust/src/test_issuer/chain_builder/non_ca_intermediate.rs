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

use rcgen::IsCa;

use crate::test_issuer::{
    CertBuilder, ChainMutator, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

/// Produces a [`TestChain`] with exactly one intermediate that asserts
/// `CA:FALSE`.
///
/// A `seed` selects which intermediate is marked as a non-CA. The resulting
/// chain is cryptographically valid, but must be rejected during verification
/// because a leaf certificate has been used to issue the certificate that
/// follows it in the chain.
#[derive(Debug, Clone)]
pub(crate) struct NonCaIntermediate {
    seed: u8,
}

impl NonCaIntermediate {
    pub(crate) fn new(seed: u8) -> Self {
        Self { seed }
    }
}

impl ChainMutator for NonCaIntermediate {
    fn intermediate<'a>(
        &self,
        builder: &mut CertBuilder<IntermediateTemplate<'a>>,
        index: u8,
        total: u8,
    ) {
        let target = self.seed % total;
        if index == target {
            builder.set_is_ca(IsCa::ExplicitNoCa);
        }
    }

    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}

    fn complete(&self, chain: TestChain) -> TestChain {
        assert!(
            !chain.intermediates.is_empty(),
            "NonCaIntermediate chain mutator requires at least 1 intermediate"
        );
        chain
    }
}
