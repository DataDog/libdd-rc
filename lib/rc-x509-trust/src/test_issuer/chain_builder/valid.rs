use crate::test_issuer::{
    CertBuilder, ChainMutator, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

/// A [`ChainMutator`] implementation that does not mutate the CSRs, resulting
/// in a valid chain.
#[derive(Debug, Default, Clone)]
pub(crate) struct ValidChain {}

impl ChainMutator for ValidChain {
    fn leaf<'a>(&self, _builder: &mut CertBuilder<LeafTemplate<'a>>) {}
    fn intermediate<'a>(&self, _builder: &mut CertBuilder<IntermediateTemplate<'a>>, _total: u8) {}
    fn complete(&self, chain: TestChain) -> TestChain {
        chain
    }
}
