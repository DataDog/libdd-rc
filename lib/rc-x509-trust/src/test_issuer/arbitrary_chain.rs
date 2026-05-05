use std::sync::Arc;

use proptest::prelude::Strategy;

use crate::test_issuer::{CertBuilder, Identity, TestCA};

#[derive(Debug)]
pub(crate) struct TestChain {
    pub(crate) root: Arc<Identity>,
    pub(crate) intermediates: Vec<Identity>,
    pub(crate) leaf: Identity,
}

/// Generate a valid chain from the `CA` root, with `n_intermediates`
/// between the root and leaf.
pub(crate) fn arbitrary_valid_chain(
    ca: &TestCA,
    n_intermediates: impl Strategy<Value = u8>,
) -> impl Strategy<Value = TestChain> {
    n_intermediates.prop_map(|n| {
        let mut intermediates = Vec::with_capacity(n as _);

        // Generate a chain of N-1 intermediates.
        for i in 0..n {
            let cert = CertBuilder::new_intermediate(
                format!("Intermediate {}", i + 1),
                intermediates.last().unwrap_or(ca.root()),
            )
            .allowed_domain("itsallbroken.com")
            .build();

            intermediates.push(cert);
        }

        // And append the leaf.
        let leaf = CertBuilder::new_leaf(
            "A Leaf Certificate",
            intermediates.last().unwrap_or(ca.root()),
        )
        .san("leaf.itsallbroken.com")
        .build();

        TestChain {
            root: Arc::clone(ca.root()),
            intermediates,
            leaf,
        }
    })
}
