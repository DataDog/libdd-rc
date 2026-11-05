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

/// Produces a [`TestChain`] whose leaf names an issuer that is absent from the
/// chain, while still linking to the chain by [`CertId`].
///
/// The two layers of chain processing disagree about what an issuer is:
///
///   * [`build_unverified_chain_for()`] follows [`IssuerCertId`] ->
///     [`CertId`] (AKI -> SKI) links.
///
///   * Verification selects candidate issuers by matching the certificate's
///     issuer name against each candidate's subject name.
///
/// This mutator exploits the gap. An attacker-controlled CA is issued with the
/// [`CertId`] of the legitimate last intermediate, so chain building accepts
/// the leaf and walks all the way to the real root. The evil CA itself is left
/// out of the chain, and because it carries its own distinct subject name, the
/// leaf names an issuer that no certificate in the chain provides:
///
/// ```text
///                 ┌──────────────┐
///                 │  Legit Root  │
///                 └──────────────┘
///                         │
///                         ▼
///                 ┌──────────────┐    ┌ ─ ─ ─ ─ ─ ─ ─
///                 │ Legit SubCA  │      Evil CA      │  (absent from chain)
///                 └──────────────┘    └ ─ ─ ─ ─ ─ ─ ─
///                         ┃                   │
///                         ┃  AKI → SKI        ▼
///                         ┃           ┏━━━━━━━━━━━━━━┓
///                         ┗━━━━━━━━━━▶┃ Orphan Leaf  ┃
///                                     ┗━━━━━━━━━━━━━━┛
/// ```
///
/// Verification therefore terminates without ever reaching a signature check -
/// there is no candidate issuer whose signature could be tested.
///
/// # Distinguishing From [`ForgedLeaf`]
///
/// [`ForgedLeaf`] mounts the same [`CertId`] substitution, but builds its evil
/// CA with [`CertBuilder::new_root`], which leaves the subject name empty - as
/// it is for the legitimate test roots. The leaf therefore does name an issuer
/// present in the chain, a signature check runs, and it fails. Here the evil
/// CA is built from an intermediate CSR, which carries a distinct subject
/// name, and no signature check happens at all.
///
/// [`CertId`]: rc_crypto::certificate::id::CertId
/// [`IssuerCertId`]: rc_crypto::certificate::id::IssuerCertId
/// [`ForgedLeaf`]: super::ForgedLeaf
/// [`build_unverified_chain_for()`]: crate::chain::build_unverified_chain_for
#[derive(Debug, Clone, Default)]
pub(crate) struct OrphanLeaf {}

impl ChainMutator for OrphanLeaf {
    fn intermediate<'a>(
        &self,
        _builder: &mut CertBuilder<IntermediateTemplate<'a>>,
        _index: u8,
        _total: u8,
    ) {
    }

    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}

    fn complete(&self, mut chain: TestChain) -> TestChain {
        let last_cert = chain
            .intermediates
            .last()
            .map(|v| v.cert())
            .unwrap_or(chain.root.cert());

        // Build the evil CA from an intermediate CSR so that it carries a
        // subject name of its own, and clone the SKI of the legitimate last
        // chain entry so that chain building links the leaf to the chain.
        let mut evil_ca = CertBuilder::new_intermediate("Evil Orphan CA", &chain.root);
        evil_ca.set_cert_id(
            last_cert
                .cert_id()
                .as_dangerous_comparable()
                .as_bytes()
                .to_vec(),
        );
        let evil_ca = evil_ca.build();

        // Issue the leaf from the evil CA, and do not add the evil CA to the
        // chain.
        chain.leaf = CertBuilder::new_leaf("Orphan Leaf", &evil_ca)
            .san("leaf.itsallbroken.com")
            .build();

        chain
    }
}
