use rc_crypto::{certificate::Certificate, keys::PrivateKey};

/// An [`Identity`] is a [`Certificate`] and the signing key for it.
#[derive(Debug)]
pub(crate) struct Identity {
    cert: Certificate,
    issuer: rcgen::CertifiedIssuer<'static, PrivateKey>,
}

impl Identity {
    pub(super) fn new(
        cert: Certificate,
        issuer: rcgen::CertifiedIssuer<'static, PrivateKey>,
    ) -> Self {
        Self { cert, issuer }
    }

    pub(crate) fn key(&self) -> &PrivateKey {
        self.issuer.key()
    }

    pub(crate) fn cert(&self) -> &Certificate {
        &self.cert
    }

    pub(super) fn issuer(&self) -> &rcgen::CertifiedIssuer<'static, PrivateKey> {
        &self.issuer
    }
}
