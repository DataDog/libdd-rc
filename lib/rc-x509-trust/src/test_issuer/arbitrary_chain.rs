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
