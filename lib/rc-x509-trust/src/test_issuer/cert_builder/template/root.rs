use rc_crypto::{certificate::Certificate, keys::PrivateKey};
use rcgen::IsCa;

use crate::test_issuer::{
    CertBuilder, Identity,
    cert_builder::{TestCertTemplate, generate_ski, serial_number},
};

/// An initialisation template for a self-signed certificate (typically a root).
#[derive(Debug, Default)]
pub(crate) struct SelfSignedTemplate;

impl TestCertTemplate for SelfSignedTemplate {
    fn build(self, cn: String, key: PrivateKey) -> Identity {
        let mut params =
            rcgen::CertificateParams::new(&[cn]).expect("invalid self-signed cert params");

        params.serial_number = Some(serial_number());
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.use_authority_key_identifier_extension = true;
        params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(generate_ski(&key));

        let issuer = rcgen::CertifiedIssuer::self_signed(params.clone(), key)
            .expect("invalid self-signed issuer");
        let cert =
            Certificate::from_pem(issuer.pem().as_bytes()).expect("valid cert for test issuer");

        Identity::new(cert, issuer)
    }
}

impl CertBuilder<SelfSignedTemplate> {
    /// Obtain a self-signed certificate.
    pub(crate) fn new_root(cn: impl Into<String>) -> Self {
        CertBuilder {
            cn: cn.into(),
            role: SelfSignedTemplate::default(),
        }
    }
}
