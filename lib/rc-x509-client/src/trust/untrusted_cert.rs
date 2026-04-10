use bytes::Bytes;
use rc_crypto::certificate::{Certificate, Fingerprint, InvalidDer};

/// An [`UntrustedCert`] is a [`Certificate`] that has been received from the RC
/// delivery server, but not yet verified by the client to chain to the root.
///
/// A [`Certificate`] can be obtained from an [`UntrustedCert`] by validating it
/// chains to the root certificate.
#[derive(Debug)]
pub struct UntrustedCert(Certificate);

impl PartialEq for UntrustedCert {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint() == other.fingerprint()
    }
}

impl UntrustedCert {
    /// Parse an [`UntrustedCert`] from DER bytes obtained from an untrusted
    /// source.
    pub fn from_der(der: impl Into<Bytes>) -> Result<Self, InvalidDer> {
        Certificate::from_der(der).map(Self)
    }

    /// Return the (unforgeable) [`Fingerprint`] that uniquely identifies the
    /// underlying [`Certificate`].
    pub fn fingerprint(&self) -> &Fingerprint {
        self.0.fingerprint()
    }
}
