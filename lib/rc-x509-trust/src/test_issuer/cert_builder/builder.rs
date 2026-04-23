use rc_crypto::{certificate::Certificate, keys::PrivateKey};
use rcgen::{CertificateSigningRequestParams, CertifiedIssuer};

use crate::test_issuer::Identity;

/// A CSR [`Template`] containing role-specific fields necessary to create a CSR
/// for the implementing type.
pub(crate) trait TestCertTemplate: std::fmt::Debug {
    fn build(self, cn: String, key: PrivateKey) -> Identity;
}

/// A helper to construct certificates for tests.
#[derive(Debug)]
pub(crate) struct CertBuilder<T> {
    /// Fields common to all templates.
    pub(super) cn: String,

    /// The template type, holding template-specific fields.
    pub(super) role: T,
}

impl<T> CertBuilder<T>
where
    T: TestCertTemplate,
{
    /// Obtain the [`Identity`] for the configured certificate template.
    pub(crate) fn build(self) -> Identity {
        let key = PrivateKey::new();
        self.role.build(self.cn, key)
    }
}

/// Always returns the same serial number, proving the test under code does not
/// distinguish certificates by their serial numbers.
pub(super) fn serial_number() -> rcgen::SerialNumber {
    rcgen::SerialNumber::from_slice(&[42])
}

/// Sign the "To Be Signed" certificate content, certifying it as trusted by
/// `parent` and returning the issued [`Identity`].
pub(super) fn sign_tbs(
    parent: &Identity,
    key: PrivateKey,
    mut tbs: CertificateSigningRequestParams,
) -> Identity {
    tbs.params.serial_number = Some(serial_number());
    tbs.params.use_authority_key_identifier_extension = true;
    tbs.params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(generate_ski(&key));

    let issuer = CertifiedIssuer::signed_by(tbs.params, key, parent.issuer()).expect("signed cert");

    let cert = Certificate::from_der(issuer.der().to_vec()).expect("valid DER");

    Identity::new(cert, issuer)
}

// This crate treats AKI and SKI as opaque values, not as trusted derivates of
// the keys or certs.
//
// In order to concretely assert this behaviour, modify the SKI such that it is
// not equal to the KeyId.
pub(super) fn generate_ski(key: &PrivateKey) -> Vec<u8> {
    let mut ski = key.public_key().key_id().to_vec();
    ski.reverse();
    ski.push(42);
    ski
}
