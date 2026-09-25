use rcgen::date_time_ymd;

use crate::test_issuer::{
    CertBuilder, ChainMutator, TestChain,
    template::{intermediate::IntermediateTemplate, leaf::LeafTemplate},
};

/// Produces a [`TestChain`] whose leaf certificate has expired.
///
/// The leaf's `notAfter` is set to a date firmly in the past. The chain is
/// cryptographically valid but must be rejected during verification because the
/// leaf is no longer within its validity period.
#[derive(Debug, Clone, Default)]
pub(crate) struct ExpiredLeaf {}

impl ChainMutator for ExpiredLeaf {
    fn intermediate<'a>(&self, _builder: &mut CertBuilder<IntermediateTemplate<'a>>, _total: u8) {}

    fn leaf<'a>(&self, builder: &mut CertBuilder<LeafTemplate<'a>>) {
        builder.set_not_after(date_time_ymd(2020, 1, 1));
    }

    fn complete(&self, chain: TestChain) -> TestChain {
        chain
    }
}
