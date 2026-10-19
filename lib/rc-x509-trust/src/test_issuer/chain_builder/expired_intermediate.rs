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

/// Produces a [`TestChain`] with exactly one expired intermediate.
///
/// A `seed` selects which intermediate receives an expired `notAfter` date. The
/// resulting chain is cryptographically valid but must be rejected during
/// verification because the expired intermediate is no longer within its
/// validity period.
#[derive(Debug, Clone)]
pub(crate) struct ExpiredIntermediate {
    seed: u8,
}

impl ExpiredIntermediate {
    pub(crate) fn new(seed: u8) -> Self {
        Self { seed }
    }
}

impl ChainMutator for ExpiredIntermediate {
    fn intermediate<'a>(
        &self,
        builder: &mut CertBuilder<IntermediateTemplate<'a>>,
        index: u8,
        total: u8,
    ) {
        let target = self.seed % total;
        if index == target {
            // Set notAfter to a date firmly in the past.
            builder.set_not_after(date_time_ymd(1969, 7, 20));
        }
    }

    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}

    fn complete(&self, chain: TestChain) -> TestChain {
        assert!(
            !chain.intermediates.is_empty(),
            "ExpiredIntermediate chain mutator requires at least 1 intermediate"
        );
        chain
    }
}
