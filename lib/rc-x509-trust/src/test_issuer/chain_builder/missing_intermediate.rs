use crate::test_issuer::{
    CertBuilder, ChainMutator, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

/// Produces a [`TestChain`] with a missing intermediate.
#[derive(Debug, Clone)]
pub(crate) struct MissingIntermediate(u8);

impl MissingIntermediate {
    pub(crate) fn new(seed: u8) -> Self {
        Self(seed)
    }

    /// Return the 0-based index of the intermediate that will be removed given
    /// an original chain of `n_intermediates`.
    pub(crate) fn will_remove_idx(&self, n_intermediates: usize) -> usize {
        self.0 as usize % n_intermediates
    }
}

impl ChainMutator for MissingIntermediate {
    fn intermediate<'a>(&self, _builder: &mut CertBuilder<IntermediateTemplate<'a>>, _total: u8) {}
    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}

    fn complete(&self, mut chain: TestChain) -> TestChain {
        assert!(
            !chain.intermediates.is_empty(),
            "MissingIntermediate chain mutator can only operate on chains with \
			at least 1 intermediate"
        );

        // Pick a random entry to remove.
        let idx = self.will_remove_idx(chain.intermediates.len());
        chain.intermediates.remove(idx);
        chain
    }
}
