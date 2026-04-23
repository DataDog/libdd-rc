use std::sync::LazyLock;

use crate::{
    cert::RootCertificate,
    test_issuer::{CertBuilder, Identity},
};

#[allow(clippy::test_attr_in_doctest)] // Not a test that needs running.
/// A "Certificate Authority" for testing:
///
/// ```rust
/// use crate::test_issuer::*;
///
/// static CA: TestCA = TestCA::new();
///
/// // tests here!
/// #[test]
/// fn test_something_with_a_root() {
///    let leaf = CertBuilder::new_leaf("Banana Signer Cert", CA.root())
///        .san("us1.example.com")
///        .build();
/// }
/// ```
///
#[derive(Debug)]
pub(crate) struct TestCA {
    root: LazyLock<Identity>,
}

impl Default for TestCA {
    fn default() -> Self {
        Self::new()
    }
}

impl TestCA {
    /// Initialise a CA with a new random root.
    pub(crate) const fn new() -> Self {
        Self {
            root: LazyLock::new(|| CertBuilder::new_root("Banana Test CA").build()),
        }
    }

    /// Return the root of trust signer [`Identity`].
    pub(crate) fn root(&self) -> &Identity {
        &self.root
    }

    /// Obtain the typed [`RootCertificate`] for this CA.
    ///
    /// This is helper and is semantically identical to constructing a
    /// [`RootCertificate`] from the `CA.root().cert()`.
    pub(crate) fn root_cert(&self) -> RootCertificate {
        RootCertificate::from_trusted_cert(self.root.cert().clone())
    }
}
