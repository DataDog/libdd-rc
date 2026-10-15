use std::iter;

use proptest::prelude::*;
use rcgen::ExtendedKeyUsagePurpose;

use crate::test_issuer::{
    CertBuilder, ChainMutator, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

/// Produces a [`TestChain`] with overridden Extended Key Usage (EKU) extensions
/// specified in the [`ChainEKUConfig`] for each role (intermediates / leaf).
#[derive(Debug, Clone)]
pub(crate) struct SetEKUs {
    apply_to: ChainEKUConfig,
}

impl SetEKUs {
    pub(crate) fn new(apply_to: ChainEKUConfig) -> Self {
        Self { apply_to }
    }
}

impl ChainMutator for SetEKUs {
    fn intermediate<'a>(
        &self,
        builder: &mut CertBuilder<IntermediateTemplate<'a>>,
        _index: u8,
        _total: u8,
    ) {
        match &self.apply_to {
            ChainEKUConfig::LeafOnly(_) => { /* nothing to do */ }
            ChainEKUConfig::IntermediatesOnly(eku) => builder.set_extended_key_usages(eku.clone()),
            ChainEKUConfig::IntermediatesAndLeaf {
                intermediate: eku,
                leaf: _,
            } => builder.set_extended_key_usages(eku.clone()),
        }
    }

    fn leaf<'a>(&self, builder: &mut CertBuilder<LeafTemplate<'a>>) {
        match &self.apply_to {
            ChainEKUConfig::LeafOnly(eku) => builder.set_extended_key_usages(eku.clone()),
            ChainEKUConfig::IntermediatesOnly(_) => { /* nothing to do */ }
            ChainEKUConfig::IntermediatesAndLeaf {
                intermediate: _,
                leaf: eku,
            } => builder.set_extended_key_usages(eku.clone()),
        }
    }

    fn complete(&self, chain: TestChain) -> TestChain {
        chain
    }
}

/// Generate an arbitrary [`ExtendedKeyUsagePurpose`] value.
pub(crate) fn arbitrary_eku() -> impl Strategy<Value = ExtendedKeyUsagePurpose> {
    prop_oneof![
        Just(ExtendedKeyUsagePurpose::Any),
        Just(ExtendedKeyUsagePurpose::ServerAuth),
        Just(ExtendedKeyUsagePurpose::ClientAuth),
        Just(ExtendedKeyUsagePurpose::CodeSigning),
        Just(ExtendedKeyUsagePurpose::EmailProtection),
        Just(ExtendedKeyUsagePurpose::TimeStamping),
        Just(ExtendedKeyUsagePurpose::OcspSigning),
    ]
}

/// Generate an arbitrary [`ChainEKUConfig`] value.
pub(crate) fn arbitrary_eku_apply_to() -> impl Strategy<Value = ChainEKUConfig> {
    prop_oneof![
        prop::collection::vec(arbitrary_eku(), 0..8).prop_map(ChainEKUConfig::LeafOnly),
        prop::collection::vec(arbitrary_eku(), 0..8).prop_map(ChainEKUConfig::IntermediatesOnly),
        (
            prop::collection::vec(arbitrary_eku(), 0..8),
            prop::collection::vec(arbitrary_eku(), 0..8)
        )
            .prop_map(
                |(intermediate, leaf)| ChainEKUConfig::IntermediatesAndLeaf { intermediate, leaf }
            ),
    ]
}

/// Which certificates in the chain have their EKU extension overridden.
#[derive(Debug, Clone)]
pub(crate) enum ChainEKUConfig {
    /// Override EKUs on intermediate and leaf certificates.
    IntermediatesAndLeaf {
        intermediate: Vec<ExtendedKeyUsagePurpose>,
        leaf: Vec<ExtendedKeyUsagePurpose>,
    },

    /// Override EKUs on the leaf certificate only.
    LeafOnly(Vec<ExtendedKeyUsagePurpose>),

    /// Override EKUs on intermediate certificates only.
    IntermediatesOnly(Vec<ExtendedKeyUsagePurpose>),
}

impl ChainEKUConfig {
    /// Return the union of all EKU bits - the set of all EKUs that appear in
    /// intermediate OR leaf certificates.
    pub(crate) fn union(&self) -> Box<dyn Iterator<Item = &'_ ExtendedKeyUsagePurpose> + '_> {
        match self {
            ChainEKUConfig::IntermediatesAndLeaf { intermediate, leaf } => {
                Box::new(intermediate.iter().chain(leaf))
            }
            ChainEKUConfig::LeafOnly(v) => Box::new(v.iter()),
            ChainEKUConfig::IntermediatesOnly(v) => Box::new(v.iter()),
        }
    }

    /// Return the leaf certificate EKUs.
    pub(crate) fn leaf(&self) -> Box<dyn Iterator<Item = &'_ ExtendedKeyUsagePurpose> + '_> {
        match self {
            ChainEKUConfig::IntermediatesAndLeaf {
                intermediate: _,
                leaf,
            } => Box::new(leaf.iter()),
            ChainEKUConfig::LeafOnly(v) => Box::new(v.iter()),
            ChainEKUConfig::IntermediatesOnly(_) => Box::new(iter::empty()),
        }
    }

    /// Return the intermediate certificate EKUs.
    pub(crate) fn intermediates(
        &self,
    ) -> Box<dyn Iterator<Item = &'_ ExtendedKeyUsagePurpose> + '_> {
        match self {
            ChainEKUConfig::IntermediatesAndLeaf {
                intermediate,
                leaf: _,
            } => Box::new(intermediate.iter()),
            ChainEKUConfig::LeafOnly(_) => Box::new(iter::empty()),
            ChainEKUConfig::IntermediatesOnly(v) => Box::new(v.iter()),
        }
    }
}
