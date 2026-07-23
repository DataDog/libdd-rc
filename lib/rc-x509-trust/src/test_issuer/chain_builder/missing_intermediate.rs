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

/// Produces a [`TestChain`] with a missing intermediate.
#[derive(Debug, Clone)]
pub(crate) struct MissingIntermediate(u8);

impl MissingIntermediate {
    pub(crate) fn new(seed: u8) -> Self {
        Self(seed)
    }

    /// Return the 0-based index of the intermediate that will be removed given
    /// an original chain of `n_intermediates`.
    pub(crate) fn will_remove_idx(&self, n_intermediates: usize) -> usize {
        self.0 as usize % n_intermediates
    }
}

impl ChainMutator for MissingIntermediate {
    fn intermediate<'a>(&self, _builder: &mut CertBuilder<IntermediateTemplate<'a>>, _total: u8) {}
    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}

    fn complete(&self, mut chain: TestChain) -> TestChain {
        assert!(
            !chain.intermediates.is_empty(),
            "MissingIntermediate chain mutator can only operate on chains with \
			at least 1 intermediate"
        );

        // Pick a random entry to remove.
        let idx = self.will_remove_idx(chain.intermediates.len());
        chain.intermediates.remove(idx);
        chain
    }
}
