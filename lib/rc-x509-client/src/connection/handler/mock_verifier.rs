use crate::connection::AttestationVerifier;

#[derive(Debug, Default)]
pub(crate) struct MockVerifier {}

impl AttestationVerifier for MockVerifier {
    fn validate(
        &self,
        _signing_cert_id: rc_crypto::certificate::id::CertId,
        _signature: rc_crypto::Signature,
        _payload: tokio_util::bytes::Bytes,
    ) -> Result<(), rc_x509_trust::trust_store::VerificationError> {
        unimplemented!()
    }
}
