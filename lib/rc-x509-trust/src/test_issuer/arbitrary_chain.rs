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

use std::sync::Arc;

use proptest::prelude::*;

use crate::test_issuer::{
    CertBuilder, Identity, TestCA,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

#[derive(Debug)]
pub(crate) struct TestChain {
    pub(crate) root: Arc<Identity>,
    pub(crate) intermediates: Vec<Identity>,
    pub(crate) leaf: Identity,
}

impl TestChain {
    pub(crate) fn build<'a>(
        ca: &'a TestCA,
        n_intermediates: u8,
        mutator: impl ChainMutator + 'a,
    ) -> Self {
        let mut intermediates = Vec::with_capacity(n_intermediates as _);

        // Generate a chain of N-1 intermediates.
        for i in 1..(n_intermediates + 1) {
            let mut builder = CertBuilder::new_intermediate(
                format!("Intermediate {}", i),
                intermediates.last().unwrap_or(ca.root()),
            )
            .allowed_domain("itsallbroken.com");

            mutator.intermediate(&mut builder, n_intermediates);
            intermediates.push(builder.build());
        }

        // And append the leaf.
        let mut builder = CertBuilder::new_leaf(
            "A Leaf Certificate",
            intermediates.last().unwrap_or(ca.root()),
        )
        .san("leaf.itsallbroken.com");

        mutator.leaf(&mut builder);

        let leaf = builder.build();

        mutator.complete(TestChain {
            root: Arc::clone(ca.root()),
            intermediates,
            leaf,
        })
    }
}

/// Hooks in [`arbitrary_chain()`] to enable implementations to modify the CSRs
/// of each certificate during chain issuance.
pub(crate) trait ChainMutator: Clone + std::fmt::Debug {
    /// Modify the [`ChainBuilder`] for an intermediate.
    ///
    /// `total` specifies the total number of intermediates / calls to this
    /// function for this chain.
    ///
    /// Calls are ordered from root to leaf.
    fn intermediate<'a>(&self, builder: &mut CertBuilder<IntermediateTemplate<'a>>, total: u8);

    /// Called once to allow modification of the chain leaf [`CertBuilder`].
    fn leaf<'a>(&self, builder: &mut CertBuilder<LeafTemplate<'a>>);

    fn complete(&self, chain: TestChain) -> TestChain;
}

/// Generate a valid chain from the `CA` root, with `n_intermediates` between
/// the root and leaf.
///
/// Optionally allow `mutator` to modify the CSRs prior to certificate issuance.
pub(crate) fn arbitrary_chain<'a>(
    ca: &'a TestCA,
    n_intermediates: impl Strategy<Value = u8> + 'a,
    mutator: impl ChainMutator + 'a,
) -> impl Strategy<Value = TestChain> + 'a {
    n_intermediates.prop_map(move |n| {
        let mutator = mutator.clone();
        TestChain::build(ca, n, mutator)
    })
}

/// A [`ChainMutator`] implementation that does not mutate the CSRs, resulting
/// in a valid chain.
#[derive(Debug, Default, Clone)]
pub(crate) struct ValidChain {}
impl ChainMutator for ValidChain {
    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}
    fn intermediate<'a>(&self, _builder: &mut CertBuilder<IntermediateTemplate<'a>>, _total: u8) {}
    fn complete(&self, chain: TestChain) -> TestChain {
        chain
    }
}

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
