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

use rcgen::date_time_ymd;

use crate::test_issuer::{
    CertBuilder, ChainMutator, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

/// Produces a [`TestChain`] whose leaf certificate is not yet valid.
///
/// The leaf's `notBefore` is set to a date far in the future. The chain is
/// cryptographically valid but must be rejected during verification because the
/// leaf's validity period has not yet started.
#[derive(Debug, Clone, Default)]
pub(crate) struct FutureValidLeaf {}

impl ChainMutator for FutureValidLeaf {
    fn intermediate<'a>(&self, _builder: &mut CertBuilder<IntermediateTemplate<'a>>, _total: u8) {}

    fn leaf<'a>(&self, builder: &mut CertBuilder<LeafTemplate<'a>>) {
        builder.set_not_before(date_time_ymd(4000, 1, 1));
    }

    fn complete(&self, chain: TestChain) -> TestChain {
        chain
    }
}
