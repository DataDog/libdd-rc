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

/// Demonstrate the untrusted nature of the [`UntrustedChain`] produced by
/// [`build_unverified_chain_for()`] by constructing a chain that produces a
/// leaf controlled by an attacker.
///
/// An attacker who constructs certificates with specific SKI values can cause
/// [`build_unverified_chain_for()`] to build and return a chain that points to
/// a leaf certificate controlled by an attacker.
///
/// Given a legitimate chain such as this:
///
/// ```text
///                          ┌──────────────┐
///                          │  Legit Root  │
///                          └──────────────┘
///                                  │
///                                  ▼
///                          ┌──────────────┐
///                          │ Legit SubCA  │
///                          └──────────────┘
///                                  │
///                                  ▼
///                          ┌──────────────┐
///                          │     Leaf     │
///                          └──────────────┘
/// ```
///
/// The [`build_unverified_chain_for()`] function can be deceived into returning
/// the following chain from the legitimate root instead:
///
/// ```text
///                 ┌──────────────┐
///                 │  Legit Root  │
///                 └──────────────┘
///                         │
///                         ▼
///                 ┌──────────────┐    ┌ ─ ─ ─ ─ ─ ─ ─
///                 │ Legit SubCA  │        Evil CA    │
///                 └──────────────┘    └ ─ ─ ─ ─ ─ ─ ─
///                         ┃                   │
///                         ┃                   ▼
///                         ┃           ┏━━━━━━━━━━━━━━┓
///                         ┗━━━━━━━━━━▶┃  Evil Leaf   ┃
///                                     ┗━━━━━━━━━━━━━━┛
/// ```
///
/// To do so:
///
///   1. An attacker creates a CA certificate, intentionally setting the
///      [`CertId`] (SKI) to the same value as a legitimate CA.
///
///   2. The attacker issues an evil leaf certificate using the evil CA, causing
///      the leaf's [`IssuerCertId`] to be equal to both the attacker's CA and
///      the legitimate CA.
///
///   3. The evil leaf certificate is presented to the client, which follows the
///      certificate's [`IssuerCertId`] -> [`CertId`] chain, all the way to the
///      legitimate root.
///
/// Any [`UntrustedChain`] must have the signature chain cryptographically
/// verified, which would fail as the `Legit SubCA` did not sigh `Evil Leaf`,
/// even though their [`IssuerCertId`] / [`CertId`] values imply it did.
///
/// [`CertId`]: rc_crypto::certificate::id::CertId
/// [`UntrustedChain`]: crate::chain::UntrustedChain
/// [`build_unverified_chain_for()`]: crate::chain::build_unverified_chain_for
#[derive(Debug, Clone, Default)]
pub(crate) struct ForgedLeaf {}

impl ChainMutator for ForgedLeaf {
    fn intermediate<'a>(&self, _builder: &mut CertBuilder<IntermediateTemplate<'a>>, _total: u8) {}

    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}

    fn complete(&self, mut chain: TestChain) -> TestChain {
        let last_cert = chain
            .intermediates
            .last()
            .map(|v| v.cert())
            .unwrap_or(chain.root.cert());

        // Create an evil CA whose SKI matches the last intermediate's SKI.
        let evil_root = CertBuilder::new_root("Evil CA")
            .set_cert_id(
                last_cert
                    .cert_id()
                    .as_dangerous_comparable()
                    .as_bytes()
                    .to_vec(),
            )
            .build();

        // Issue an evil leaf from the evil CA. The evil leaf's AKI will
        // equal the legitimate intermediate's SKI.
        let evil_leaf = CertBuilder::new_leaf("Evil Leaf", &evil_root)
            .san("leaf.itsallbroken.com")
            .build();

        // Replace the legitimate leaf with the evil leaf.
        chain.leaf = evil_leaf;
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
