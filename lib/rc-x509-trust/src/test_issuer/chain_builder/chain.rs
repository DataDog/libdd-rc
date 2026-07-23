use std::sync::Arc;

use proptest::prelude::*;

use crate::test_issuer::{
    CertBuilder, Identity, TestCA,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

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

    /// Called once to allow modification of the final chain.
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

/// A generated chain for testing.
#[derive(Debug)]
pub(crate) struct TestChain {
    /// The trust anchor for this chain.
    pub(crate) root: Arc<Identity>,

    /// 0 or more intermediate certificates, ordered from root to leaf.
    pub(crate) intermediates: Vec<Identity>,

    /// The leaf certificate, signed by the last `intermediates` entry, or the
    /// root if empty.
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
