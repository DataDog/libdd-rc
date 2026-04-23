use rc_crypto::{certificate::csr::CertificateSigningRequest, keys::PrivateKey};
use rcgen::IsCa;

use crate::test_issuer::{
    CertBuilder, Identity,
    cert_builder::{TestCertTemplate, sign_tbs},
};

/// An initialisation template for a leaf signer certificate.
#[derive(Debug)]
pub(crate) struct LeafTemplate<'a> {
    parent: &'a Identity,
    san: Option<String>,
}

impl<'a> TestCertTemplate for LeafTemplate<'a> {
    fn build(self, cn: String, key: PrivateKey) -> Identity {
        let csr = CertificateSigningRequest::new_leaf(
            &key,
            &cn,
            self.san.as_ref().expect("no san provided for leaf cert"),
        )
        .expect("invalid CSR");

        let mut tbs = rcgen::CertificateSigningRequestParams::from_pem(&csr.as_pem_string())
            .expect("invalid TBS");

        tbs.params.is_ca = IsCa::ExplicitNoCa;

        sign_tbs(self.parent, key, tbs)
    }
}

impl<'a> CertBuilder<LeafTemplate<'a>> {
    /// Initialise a new leaf signer certificate template.
    pub(crate) fn new_leaf(cn: impl Into<String>, parent: &'a Identity) -> Self {
        CertBuilder {
            cn: cn.into(),
            role: LeafTemplate { parent, san: None },
        }
    }

    /// Set the SAN domain for this signer cert (required).
    pub(crate) fn san(mut self, san: impl Into<String>) -> Self {
        self.role.san = Some(san.into());
        self
    }
}
