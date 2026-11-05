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

/// Produces a [`TestChain`] whose leaf certificate carries a `notAfter` that
/// predates the unix epoch.
///
/// The verifier represents certificate validity bounds as a count of seconds
/// since the unix epoch, so a pre-epoch timestamp has no representation. Such
/// a certificate is rejected as malformed rather than as expired - the
/// distinction the [`ExpiredLeaf`] mutator relies on.
///
/// [`ExpiredLeaf`]: super::ExpiredLeaf
#[derive(Debug, Clone, Default)]
pub(crate) struct PreEpochLeaf {}

impl ChainMutator for PreEpochLeaf {
    fn intermediate<'a>(
        &self,
        _builder: &mut CertBuilder<IntermediateTemplate<'a>>,
        _index: u8,
        _total: u8,
    ) {
    }

    fn leaf<'a>(&self, builder: &mut CertBuilder<LeafTemplate<'a>>) {
        builder.set_not_after(date_time_ymd(1969, 7, 20));
    }

    fn complete(&self, chain: TestChain) -> TestChain {
        chain
    }
}
