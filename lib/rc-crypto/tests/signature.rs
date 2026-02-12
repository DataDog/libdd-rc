use std::sync::{Arc, LazyLock};

use aws_lc_rs::rand;
use proptest::prelude::*;
use rc_crypto::{
    Signer,
    certificate::{Certificate, csr::CertificateSigningRequest},
    keys::PrivateKey,
};
use rcgen::{CertificateParams, CertificateSigningRequestParams, CertifiedIssuer, SerialNumber};

/// [`TEST_KEY`] is a randomly generated keypair for use in tests.
static TEST_KEY: LazyLock<Arc<PrivateKey>> = LazyLock::new(|| Arc::new(PrivateKey::new()));

/// [`TEST_ISSUER`] is a [`TestIssuer`] used to certify [`TEST_KEY`], producing
/// [`TEST_CERT`].
static TEST_ISSUER: LazyLock<Arc<CertifiedIssuer<'static, PrivateKey>>> = LazyLock::new(|| {
    let key = PrivateKey::new();
    let mut params = CertificateParams::new(&["Bananas Test CA".to_string()])
        .expect("invalid self-signed cert params");

    let mut sn = [0_u8; 16];
    rand::fill(&mut sn).expect("rand available");
    params.serial_number = Some(SerialNumber::from_slice(&sn));

    Arc::new(CertifiedIssuer::self_signed(params, key).expect("invalid self-signed issuer"))
});

/// A [`Certificate`] for [`TEST_KEY`] issued by [`TEST_ISSUER`].
static TEST_CERT: LazyLock<Certificate> = LazyLock::new(|| {
    let csr = CertificateSigningRequest::new_leaf(&TEST_KEY, "bananas", "itsallbroken.com")
        .expect("valid CSR");

    let mut tbs =
        CertificateSigningRequestParams::from_pem(&csr.as_pem_string()).expect("invalid CSR");

    let mut sn = [0_u8; 16];
    rand::fill(&mut sn).expect("rand available");
    tbs.params.serial_number = Some(SerialNumber::from_slice(&sn));

    Certificate::from(tbs.signed_by(&*TEST_ISSUER).expect("failed to sign cert"))
});

proptest! {
    #[test]
    fn prop_generate_sign_verify(
        mut payload in prop::collection::vec(any::<u8>(), 0..2049),
    ) {
        // Generate a random private key.
        let key = PrivateKey::new();

        // Sign the payload, obtaining a signature.
        let sig = key.sign(&payload);

        // Invariant:  the public portion of "key" MUST be able to verify
        // the signature.
        assert!(key.public_key().verify(&payload, &sig).is_ok());

        // Tamper with the payload.
        payload.push(42);

        // Invariant: verification of a modified payload MUST fail.
        assert!(key.public_key().verify(&payload, &sig).is_err());
    }

    /// Assert the PublicKey extracted from a Certificate can be used to verify
    /// data signed by the keypair.
    #[test]
    fn prop_cert_verify_signature(
        data in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let sig = TEST_KEY.sign(&data);
        let public = TEST_CERT.public_key();

        // Extracted key IDs MUST match the source key's ID.
        assert_eq!(public.key_id(), TEST_KEY.public_key().key_id());

        // Signatures MUST be verifiable by the public key extracted from the
        // certificate.
        assert!(public.verify(&data, &sig).is_ok());
    }
}
