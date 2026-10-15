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

/// Produces a [`TestChain`] with two intermediate certificates whose SKI and
/// AKI values form a cycle:
///
/// ```text
///     int_a.SKI == int_b.AKI
///     int_b.SKI == int_a.AKI
/// ```
///
/// A naïve chain builder that follows AKI→SKI links without cycle detection
/// would loop forever between these two certificates.
///
/// The resulting chain has invalid signatures.
///
/// [`CertId`]: rc_crypto::certificate::id::CertId
/// [`IssuerCertId`]: rc_crypto::certificate::id::IssuerCertId
#[derive(Debug, Clone, Default)]
pub(crate) struct SelfReferentialCertIds {}

impl ChainMutator for SelfReferentialCertIds {
    fn intermediate<'a>(
        &self,
        _builder: &mut CertBuilder<IntermediateTemplate<'a>>,
        _index: u8,
        _total: u8,
    ) {
    }

    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}

    fn complete(&self, mut chain: TestChain) -> TestChain {
        assert!(
            chain.intermediates.len() >= 2,
            "SelfReferentialCertIds chain mutator requires at least 2 intermediate"
        );

        // Two distinct SKI values that will cross-reference each other.
        let ski_a: Vec<u8> = vec![4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4];
        let ski_b: Vec<u8> = vec![2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2];

        // Build intermediate A with:
        //
        // 		SKI = ski_a
        // 		AKI = ski_b
        //
        let mut signer_for_a = CertBuilder::new_root("Loop Signer B");
        signer_for_a.set_cert_id(ski_b.clone());
        let signer_for_a = signer_for_a.build();

        let mut int_a = CertBuilder::new_intermediate("Loop Intermediate A", &signer_for_a);
        int_a.set_cert_id(ski_a.clone());
        let int_a = int_a.build();

        // Build intermediate B
        //
        // 		SKI = ski_b
        // 		AKI = ski_a
        //
        let mut signer_for_b = CertBuilder::new_root("Loop Signer A");
        signer_for_b.set_cert_id(ski_a);
        let signer_for_b = signer_for_b.build();

        let mut int_b = CertBuilder::new_intermediate("Loop Intermediate B", &signer_for_b);
        int_b.set_cert_id(ski_b);
        let int_b = int_b.build();

        // Replace the last two intermediates with the cyclic pair.
        let len = chain.intermediates.len();
        chain.intermediates[len - 2] = int_a;
        chain.intermediates[len - 1] = int_b;

        // Re-issue the leaf signed by the new last intermediate so the
        // leaf's AKI correctly references int_b's SKI.
        let leaf = CertBuilder::new_leaf("Leaf", &chain.intermediates[len - 1])
            .san("leaf.itsallbroken.com")
            .build();
        chain.leaf = leaf;

        chain
    }
}
