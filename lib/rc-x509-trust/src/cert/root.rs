use rc_crypto::certificate::Certificate;

/// A root "trust anchor" certificate from which all trust is descended.
#[derive(Debug)]
pub struct RootCertificate(Certificate);

impl RootCertificate {
    /// Mark the provided [`Certificate`] as a root of trust.
    pub fn from_trusted_cert(c: Certificate) -> Self {
        Self(c)
    }
}

impl std::ops::Deref for RootCertificate {
    type Target = Certificate;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
