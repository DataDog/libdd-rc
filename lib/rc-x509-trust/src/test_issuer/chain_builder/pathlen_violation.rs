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

/// Produces a [`TestChain`] that violates the pathLen basic constraint.
///
/// Every intermediate is issued with `pathLen=0`, meaning it is only permitted
/// to sign leaf certificates. When the chain contains two or more
/// intermediates the first intermediate has signed a second intermediate,
/// violating its `pathLen=0` constraint.
///
/// ```text
///                      ┌──────────────┐
///                      │     Root     │
///                      └──────────────┘
///                              │
///                              ▼
///                      ┌──────────────┐
///                      │ Intermediate │  pathLen=0
///                      └──────────────┘
///                              │
///                              ▼  ← violates pathLen=0
///                      ┌──────────────┐
///                      │ Intermediate │  pathLen=0
///                      └──────────────┘
///                              │
///                              ▼
///                      ┌──────────────┐
///                      │     Leaf     │
///                      └──────────────┘
/// ```
///
#[derive(Debug, Clone, Default)]
pub(crate) struct PathLenViolation {}

impl ChainMutator for PathLenViolation {
    fn intermediate<'a>(&self, builder: &mut CertBuilder<IntermediateTemplate<'a>>, _total: u8) {
        builder.set_path_len(0);
    }

    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}

    fn complete(&self, chain: TestChain) -> TestChain {
        assert!(
            chain.intermediates.len() >= 2,
            "PathLenViolation chain mutator requires at least 2 intermediates"
        );
        chain
    }
}
