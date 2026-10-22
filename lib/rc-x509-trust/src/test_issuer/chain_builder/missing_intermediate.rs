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

use std::sync::Mutex;

use crate::test_issuer::{
    CertBuilder, ChainMutator, Identity, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

/// Produces a [`TestChain`] with a missing intermediate.
#[derive(Debug)]
pub(crate) struct MissingIntermediate {
    seed: u8,
    dropped: Mutex<Option<Identity>>,
}

impl MissingIntermediate {
    pub(crate) fn new(seed: u8) -> Self {
        Self {
            seed,
            dropped: Mutex::new(None),
        }
    }

    /// Obtain the [`Identity`] that was removed from the chain by this mutator.
    pub(crate) fn take_dropped(&self) -> Option<Identity> {
        self.dropped.lock().unwrap().take()
    }
}

impl ChainMutator for MissingIntermediate {
    fn intermediate<'a>(
        &self,
        _builder: &mut CertBuilder<IntermediateTemplate<'a>>,
        _index: u8,
        _total: u8,
    ) {
    }
    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}

    fn complete(&self, mut chain: TestChain) -> TestChain {
        assert!(
            !chain.intermediates.is_empty(),
            "MissingIntermediate chain mutator can only operate on chains with \
			at least 1 intermediate"
        );

        // Pick a random entry to remove.
        let idx = self.seed as usize % chain.intermediates.len();
        let dropped = chain.intermediates.remove(idx);

        // Retain the dropped cert for later asserts.
        *self.dropped.lock().unwrap() = Some(dropped);

        chain
    }
}
