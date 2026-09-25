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
