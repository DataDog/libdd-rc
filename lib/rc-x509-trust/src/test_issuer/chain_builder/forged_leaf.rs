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
