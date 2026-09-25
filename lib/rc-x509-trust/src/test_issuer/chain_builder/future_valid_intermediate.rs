use std::cell::Cell;

use rcgen::date_time_ymd;

use crate::test_issuer::{
    CertBuilder, ChainMutator, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

/// Produces a [`TestChain`] with exactly one not-yet-valid intermediate.
///
/// A `seed` selects which intermediate receives a `notBefore` date far in the
/// future. The resulting chain is cryptographically valid but must be rejected
/// during verification because the intermediate's validity period has not yet
/// started.
#[derive(Debug, Clone)]
pub(crate) struct FutureValidIntermediate {
    seed: u8,
    call_index: Cell<u8>,
}

impl FutureValidIntermediate {
    pub(crate) fn new(seed: u8) -> Self {
        Self {
            seed,
            call_index: Cell::new(0),
        }
    }
}

impl ChainMutator for FutureValidIntermediate {
    fn intermediate<'a>(&self, builder: &mut CertBuilder<IntermediateTemplate<'a>>, total: u8) {
        let idx = self.call_index.get();
        self.call_index.set(idx + 1);

        let target = self.seed % total;
        if idx == target {
            // Set notBefore to a date far in the future.
            builder.set_not_before(date_time_ymd(4000, 1, 1));
        }
    }

    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}

    fn complete(&self, chain: TestChain) -> TestChain {
        assert!(
            !chain.intermediates.is_empty(),
            "FutureValidIntermediate chain mutator requires at least 1 intermediate"
        );
        chain
    }
}
