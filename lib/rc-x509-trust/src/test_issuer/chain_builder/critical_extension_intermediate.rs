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

use rcgen::CustomExtension;

use crate::test_issuer::{
    CertBuilder, ChainMutator, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

/// An OID under the private enterprise arc that no verifier assigns a meaning
/// to, used to construct an extension that cannot be processed.
const UNKNOWN_EXTENSION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];

/// Build an extension carrying [`UNKNOWN_EXTENSION_OID`], marked critical.
pub(crate) fn unknown_critical_extension() -> CustomExtension {
    let mut ext = CustomExtension::from_oid_content(UNKNOWN_EXTENSION_OID, vec![0xde, 0xad]);
    ext.set_criticality(true);
    ext
}

/// Produces a [`TestChain`] with exactly one intermediate carrying an
/// extension that is marked critical, but which the verifier does not
/// understand.
///
/// A `seed` selects which intermediate is affected. See
/// [`CriticalExtensionLeaf`] for why this must be rejected.
///
/// [`CriticalExtensionLeaf`]: super::CriticalExtensionLeaf
#[derive(Debug, Clone)]
pub(crate) struct CriticalExtensionIntermediate {
    seed: u8,
}

impl CriticalExtensionIntermediate {
    pub(crate) fn new(seed: u8) -> Self {
        Self { seed }
    }
}

impl ChainMutator for CriticalExtensionIntermediate {
    fn intermediate<'a>(
        &self,
        builder: &mut CertBuilder<IntermediateTemplate<'a>>,
        index: u8,
        total: u8,
    ) {
        let target = self.seed % total;
        if index == target {
            builder.add_custom_extension(unknown_critical_extension());
        }
    }

    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}

    fn complete(&self, chain: TestChain) -> TestChain {
        assert!(
            !chain.intermediates.is_empty(),
            "CriticalExtensionIntermediate chain mutator requires at least 1 intermediate"
        );
        chain
    }
}
