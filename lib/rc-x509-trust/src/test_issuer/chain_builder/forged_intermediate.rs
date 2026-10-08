use crate::test_issuer::{
    CertBuilder, ChainMutator, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

/// Produces a [`TestChain`] with an attacker-controlled intermediate injected
/// at a random position, analogous to the leaf-level attack in [`ForgedLeaf`].
///
/// Given a legitimate chain:
///
/// ```text
///                      ┌──────────────┐
///                      │  Legit Root  │
///                      └──────────────┘
///                              │
///                              ▼
///                      ┌──────────────┐
///                      │ Legit SubCA₁ │
///                      └──────────────┘
///                              │
///                              ▼
///                      ┌──────────────┐
///                      │ Legit SubCA₂ │
///                      └──────────────┘
///                              │
///                              ▼
///                      ┌──────────────┐
///                      │     Leaf     │
///                      └──────────────┘
/// ```
///
/// The mutator replaces everything from a chosen intermediate onwards with an
/// attacker-controlled sub-chain whose AKI/SKI values link to the legitimate
/// parent:
///
/// ```text
///              ┌──────────────┐
///              │  Legit Root  │
///              └──────────────┘
///                      │
///                      ▼
///              ┌──────────────┐    ┌ ─ ─ ─ ─ ─ ─ ─
///              │ Legit SubCA₁ │       Evil Root   │
///              └──────────────┘    └ ─ ─ ─ ─ ─ ─ ─
///                      ┃                  │
///                      ┃                  ▼
///                      ┃          ┏━━━━━━━━━━━━━━┓
///                      ┗━━━━━━━━━▶┃  Evil SubCA  ┃
///                                 ┗━━━━━━━━━━━━━━┛
///                                         │
///                                         ▼
///                                 ┏━━━━━━━━━━━━━━┓
///                                 ┃  Evil Leaf   ┃
///                                 ┗━━━━━━━━━━━━━━┛
/// ```
///
/// Cryptographic verification rejects this chain because `Legit SubCA₁` did
/// not sign `Evil SubCA`, despite their [`CertId`] / [`IssuerCertId`] values
/// implying otherwise.
///
/// [`ForgedLeaf`]: super::ForgedLeaf
/// [`CertId`]: rc_crypto::certificate::id::CertId
/// [`IssuerCertId`]: rc_crypto::certificate::id::IssuerCertId
#[derive(Debug, Clone)]
pub(crate) struct ForgedIntermediate {
    seed: u8,
}

impl ForgedIntermediate {
    pub(crate) fn new(seed: u8) -> Self {
        Self { seed }
    }
}

impl ChainMutator for ForgedIntermediate {
    fn intermediate<'a>(&self, _builder: &mut CertBuilder<IntermediateTemplate<'a>>, _total: u8) {}

    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}

    fn complete(&self, mut chain: TestChain) -> TestChain {
        assert!(
            !chain.intermediates.is_empty(),
            "ForgedIntermediate chain mutator requires at least 1 intermediate"
        );

        // Pick which intermediate to replace.
        let idx = self.seed as usize % chain.intermediates.len();

        // The parent is the certificate that the replaced intermediate claims
        // to chain to (via AKI → SKI).
        let parent_cert = if idx == 0 {
            chain.root.cert()
        } else {
            chain.intermediates[idx - 1].cert()
        };

        // Create an evil CA whose SKI matches the legitimate parent's SKI.
        let evil_root = CertBuilder::new_root("Evil CA")
            .set_cert_id(
                parent_cert
                    .cert_id()
                    .as_dangerous_comparable()
                    .as_bytes()
                    .to_vec(),
            )
            .build();

        // Issue an evil intermediate from the evil CA — its AKI will match
        // the legitimate parent's SKI.
        let evil_intermediate = CertBuilder::new_intermediate("Evil Intermediate", &evil_root)
            .allowed_domain("itsallbroken.com")
            .build();

        // Issue an evil leaf from the evil intermediate.
        let evil_leaf = CertBuilder::new_leaf("Evil Leaf", &evil_intermediate)
            .san("leaf.itsallbroken.com")
            .build();

        // Replace from idx onwards with the single evil intermediate.
        chain.intermediates.truncate(idx);
        chain.intermediates.push(evil_intermediate);
        chain.leaf = evil_leaf;
        chain
    }
}
