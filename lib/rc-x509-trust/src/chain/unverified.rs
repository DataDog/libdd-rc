use std::sync::Arc;

use rc_crypto::certificate::Certificate;

/// An unverified candidate chain for some leaf [`Certificate`]. to some root.
///
/// This type contains the chain of intermediates only.
///
/// An [`UntrustedChain`] is not yet cryptographically verified and must not be
/// trusted.
///
/// ## Chain Value
///
/// This type holds a partial path from a leaf [`Certificate`] to a root, but
/// includes neither:
///
/// ```text
///                 <leaf> -> [SubCA 2, SubCA 1] -> <root>
/// ```
///
/// Where `<leaf>` and `<root>` are implicit / not retained within the
/// [`UntrustedChain`] and must be provided alongside it for any trust
/// operations.
#[derive(Debug)]
pub(crate) struct UntrustedChain(Vec<Arc<Certificate>>);

impl UntrustedChain {
    /// Borrow the chain content.
    pub(crate) fn as_slice(&self) -> &[Arc<Certificate>] {
        &self.0
    }
}

impl From<Vec<Arc<Certificate>>> for UntrustedChain {
    fn from(value: Vec<Arc<Certificate>>) -> Self {
        Self(value)
    }
}
