// Copyright 2026-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use hashbrown::HashMap;
use rc_crypto::{
    Signature,
    certificate::id::{CertId, DangerousComparableId},
    keys::SignatureVerifyErr,
};
use rc_x509_roots::RootCertificate;
use rc_x509_trust::{
    EndpointHostname,
    cert::{UntrustedCert, UntrustedCertBytes},
    chain::{ChainBuildError, ChainVerifyError},
    trust_store::VerificationError,
};
use std::{iter, num::NonZeroUsize, sync::Arc};
use tracing::{debug, error, trace};

use crate::{
    Payload,
    codec::{DispatchViolation, ProtocolError, VerifyChainFailed},
    connection::AttestationVerifier,
    host_runtime::CorrelationId,
};

// TODO(dom): limit number and / or size of deferred payloads

/// A [`Deferred`] verification for a single payload.
///
/// This type captures all inputs necessary to retry verification in the future.
/// All fields are untrusted until successfully verified.
#[derive(Debug)]
pub(super) struct Deferred {
    /// The RPC correlation ID that delivered this payload.
    pub correlation_id: CorrelationId,

    /// The signing / leaf [`CertId`] that is claimed to have produced
    /// `signature` over `payload`.
    pub signing_cert_id: CertId,

    /// The signature over `payload` the signer certificate claims to have
    /// generated.
    pub signature: Signature,

    /// The message payload content.
    pub payload: Payload,
}

/// A set of [`Deferred`] validation requests that have been identified as
/// retryable after previously missing certificates have been obtained.
///
/// This type holds the only copy of the deferred inputs - dropping this type
/// without processing the content causes the in-flight messages to be lost.
#[derive(Debug)]
#[must_use = "dropping deferred validation iterator loses in-flight messages"]
pub(super) struct DeferredValidations(iter::Flatten<std::vec::IntoIter<Vec<Deferred>>>);

impl Iterator for DeferredValidations {
    type Item = Deferred;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

/// The reason for a verification failure.
///
/// If [`Self::MissingCert`] is returned, subsequent calls for the same signer
/// [`CertId`] will return [`Self::AlreadyMissingCert`] until the deferred
/// payloads are taken using [`DeferredVerifierState::add_certs()`].
#[derive(Debug)]
pub(super) enum VerifyFailure {
    /// The specified [`CertId`] is not known locally, so the verification
    /// cannot complete.
    ///
    /// The returned [``]
    ///
    /// Fetch this certificate and call [`DeferredVerifierState::add_certs()`]
    /// to complete verification.
    MissingCert {
        /// The certificate that is required for verification to complete.
        ///
        /// This may be a leaf or intermediate certificate. It may or may not
        /// exist (i.e. if an attacker injects a fraudulent dispatch request).
        missing_cert_id: CertId,

        /// The number of deferred payloads waiting for this [`CertId`] in order
        /// to complete verification.
        deferred_count: NonZeroUsize,
    },

    /// The verification failed for a terminal reason and the included
    /// [`ProtocolError`] should be returned to the server.
    Rejected(Box<ProtocolError>),
}

/// A [`DeferredVerifierState`] adds stateful payload verification to an
/// underlying stateless [`AttestationVerifier`] for verification requests that
/// cannot complete due to missing local certificates.
///
/// In order for a (valid) [`DeferredVerifierState::verify_or_defer()`] call to
/// complete successfully, all certificates from root to leaf must be locally
/// available to the [`AttestationVerifier`]. If there are one or more missing
/// certificates, this type tracks the in-flight request state and returns it
/// for reprocessing once the missing certificate is fed into
/// [`DeferredVerifierState::add_certs()`] in the future.
///
/// # Bounds
///
/// ## Max Verification Attempts
///
/// This type does not constrain the number of attempts to validate a specific
/// [`Deferred`] payload. Instead this is bounded indirectly by the chain length
/// enforced within the [`AttestationVerifier`] itself, meaning any valid chain
/// will eventually be processed, and maliciously constructed requests will fail
/// with a chain length error after bounded validation attempts.
#[derive(Debug, Default)]
pub(super) struct DeferredVerifierState {
    deferred: HashMap<DangerousComparableId<'static, CertId>, Vec<Deferred>>,
}

impl DeferredVerifierState {
    /// Add `unparsed_certs` to `verifier`, returning a set of
    /// [`DeferredValidations`] if one or more certificates have previously
    /// blocked a verification from proceeding.
    ///
    /// # Deferred Validations
    ///
    /// If this call returns [`Some`] with a set of [`DeferredValidations`], the
    /// caller MUST process them as soon as reasonably possible.
    ///
    /// Failing to process the [`DeferredValidations`] causes the in-flight
    /// message state to be lost, and any delay in processing manifests as
    /// message latency.
    ///
    /// # Errors
    ///
    /// If an error is returned, any deferred validations that could have
    /// continued are lost and the [`DeferredVerifierState`] should be
    /// considered poisoned and unusable (consistent with the client failure
    /// mode of "disconnect and reset" when a bad cert is sent by the server).
    #[must_use = "dropping deferred validation iterator loses in-flight messages"]
    pub(crate) fn add_certs<V>(
        &mut self,
        verifier: &V,
        unparsed_certs: Vec<UntrustedCertBytes>,
    ) -> Result<Option<DeferredValidations>, Box<ProtocolError>>
    where
        V: AttestationVerifier,
    {
        debug!(n = unparsed_certs.len(), "processing batched cert push");

        let mut to_verify = Vec::new();
        let mut certs = Vec::with_capacity(unparsed_certs.len());
        for bytes in unparsed_certs {
            let cert = match UntrustedCertBytes::parse(bytes) {
                Ok(v) => v,
                Err(e) => {
                    error!(error=%e, "failed to parse certificate");

                    return Err(Box::new(ProtocolError::CertPush(
                        crate::codec::CertPushViolation::InvalidDer(e.to_string()),
                    )));
                }
            };

            let cert_id = cert.cert_id();

            trace!(
                %cert_id,
                "successfully parsed untrusted cert",
            );

            if let Some(v) = self.deferred.remove(cert_id) {
                debug!(
                    %cert_id,
                    n_deferred = v.len(),
                    "pushed cert will be used for deferred verification"
                );

                to_verify.push(v);
            }

            certs.push(cert);
        }

        verifier.add(certs.into_iter());

        if to_verify.is_empty() {
            return Ok(None);
        }

        Ok(Some(DeferredValidations(to_verify.into_iter().flatten())))
    }

    /// Attempt to authenticate `payload` using `verifier`.
    ///
    /// There are three high level outcomes to this call:
    ///
    ///  1. Payload is verified (happy path): the payload is valid and
    ///     authentic, and should be dispatched to the host application.
    ///
    ///  2. Payload is identified as invalid / untrusted: the client should
    ///     refuse to process this untrusted payload.
    ///
    ///  3. Local state is missing, preventing verification from completing. The
    ///     payload authenticity is unknown.
    ///
    /// This call only ever returns [`Ok`] when the payload is known to be
    /// trustworthy (outcome 1).
    ///
    /// If this call returns [`Err`] with [`VerifyFailure::MissingCert`] then
    /// the verification cannot complete until the referenced certificate is
    /// obtained, and the request (payload + verification inputs) is retained
    /// internally until the appropriate certificate is passed to
    /// [`Self::add_certs()`] (outcome 3).
    ///
    /// If this call returns [`Err`] with any other [`VerifyFailure`], then
    /// `payload` is untrusted (potentially proven as fraudulent) and must not
    /// be delivered to the host application (outcome 2).
    pub(crate) fn verify_or_defer<V>(
        &mut self,
        verifier: &V,
        endpoint_hostname: &EndpointHostname,
        correlation_id: CorrelationId,
        signing_cert_id: CertId,
        signature: Signature,
        payload: Payload,
    ) -> Result<Payload, VerifyFailure>
    where
        V: AttestationVerifier,
    {
        match verifier.verify(&signing_cert_id, &signature, &payload, endpoint_hostname) {
            Ok(v) => v,
            Err(VerificationError::MissingLeafCert(missing_cert_id)) => {
                // The signing cert isn't in the local cache.
                //
                // Defer verification until the appropriate cert is pushed by
                // the server.
                return Err(self.add_deferred(
                    missing_cert_id,
                    Deferred {
                        correlation_id,
                        signing_cert_id,
                        signature,
                        payload,
                    },
                ));
            }
            Err(VerificationError::ChainBuild(ChainBuildError::MissingIntermediate(
                missing_cert_id,
            ))) => {
                // The specified intermediate cert isn't in the local cache.
                //
                // Defer verification until the appropriate cert is pushed by
                // the server.
                return Err(self.add_deferred(
                    missing_cert_id.as_cert_id().to_owned(),
                    Deferred {
                        correlation_id,
                        signing_cert_id,
                        signature,
                        payload,
                    },
                ));
            }
            Err(VerificationError::ChainBuild(ChainBuildError::ExcessivelyLongChain)) => {
                // No candidate chain could be built, because the number of
                // intermediates exceeds the maximum allowed chain length.
                return Err(VerifyFailure::Rejected(Box::new(ProtocolError::Dispatch(
                    correlation_id,
                    DispatchViolation::ExcessivelyLongChain {
                        leaf_cert_id: signing_cert_id.as_dangerous_comparable().as_bytes().into(),
                    },
                ))));
            }
            Err(VerificationError::ChainVerify {
                root_cert,
                intermediates,
                leaf_cert,
                error,
            }) => {
                // Verifying chain trust failed, and "error" describes why.
                return Err(VerifyFailure::Rejected(Box::new(
                    chain_verify_error_to_protocol_violation(
                        correlation_id,
                        root_cert,
                        intermediates,
                        leaf_cert,
                        error,
                    ),
                )));
            }
            Err(VerificationError::Signature(SignatureVerifyErr)) => {
                // The signature does not match the payload.
                return Err(VerifyFailure::Rejected(Box::new(ProtocolError::Dispatch(
                    correlation_id,
                    DispatchViolation::SignatureMismatch,
                ))));
            }
        };

        Ok(payload)
    }

    /// Private helper to register a [`Deferred`] to be processed once
    /// `missing_cert_id` is observed.
    fn add_deferred(&mut self, missing_cert_id: CertId, params: Deferred) -> VerifyFailure {
        let queue = self
            .deferred
            .entry(missing_cert_id.as_dangerous_comparable().into_owned())
            .or_default();

        queue.push(params);

        VerifyFailure::MissingCert {
            missing_cert_id,
            deferred_count: NonZeroUsize::new(queue.len()).unwrap(),
        }
    }
}

/// Convert a [`ChainVerifyError`] into a [`ProtocolError`] with the associated
/// reporting context.
fn chain_verify_error_to_protocol_violation(
    correlation_id: CorrelationId,
    root_cert: Box<RootCertificate>,
    intermediates: Vec<Arc<UntrustedCert>>,
    leaf_cert: Arc<UntrustedCert>,
    error: ChainVerifyError,
) -> ProtocolError {
    ProtocolError::Dispatch(
        correlation_id,
        DispatchViolation::VerifyChainFailed(VerifyChainFailed {
            root_cert_id: root_cert
                .cert_id()
                .as_dangerous_comparable()
                .as_bytes()
                .into(),
            intermediate_cert_id: intermediates
                .into_iter()
                .map(|v| v.cert_id().as_dangerous_comparable().as_bytes().into())
                .collect(),
            leaf_cert_id: leaf_cert
                .cert_id()
                .as_dangerous_comparable()
                .as_bytes()
                .into(),
            error,
        }),
    )
}

#[cfg(test)]
mod tests {
    use crate::{connection::mock_verifier::MockVerifier, tests::arbitrary_bytes};

    use super::*;

    use assert_matches::assert_matches;
    use proptest::prelude::*;
    use rc_x509_test_helpers::test_issuer::{TestCA, TestChain, ValidChain, arbitrary_chain};
    use rc_x509_trust::trust_store::MemoryCertCache;
    use tokio_util::bytes::Bytes;

    static CA: TestCA = TestCA::new();
    const CORRELATION_ID: CorrelationId = CorrelationId::new(42);

    /// A happy-path test where the [`DeferredVerifierState`] has nothing to do;
    /// the payload is passed to the underlying [`AttestationVerifier`] which
    /// signals the payload is trusted.
    #[test]
    fn test_immediate_verify() {
        let mut verifier = DeferredVerifierState::default();
        let hostname = EndpointHostname::try_from("itsallbroken.com".to_string()).unwrap();

        let mock = MockVerifier::default().with_verify_ret([Ok(())]);
        let chain = TestChain::default();
        let payload = vec![42; 100];

        let got = verifier
            .verify_or_defer(
                &mock,
                &hostname,
                CORRELATION_ID,
                chain.leaf.cert().cert_id().to_owned(),
                Signature::try_from([13_u8; 100].as_slice()).unwrap(),
                Payload::from(payload.clone()),
            )
            .expect("must succeed");

        assert_eq!(got.as_bytes(), payload.as_slice());
    }

    proptest! {
        /// Drive the expected "discover missing cert -> ask for cert -> repeat
        /// until success" process for deferred verifications, for every cert in
        /// a randomised chain, until verification success (as an integration
        /// test the real trust store verifier).
        #[test]
        fn prop_deferred_verify_integration(
            chain in arbitrary_chain(&CA, 0..=5_u8, ValidChain::default()),
            payload in arbitrary_bytes(0..257),
        ) {
            test_prop_deferred_verify_integration(chain, payload);
        }

        /// Pushing a batch of certificates containing one unparsable DER input
        /// causes an error to be returned.
        #[test]
        fn prop_add_bad_certs(
            chain in arbitrary_chain(&CA, 0..=5_u8, ValidChain::default()),
            bad_der in arbitrary_bytes(0..32),
            position in any::<prop::sample::Index>(),
        ) {
            test_prop_add_bad_certs(chain, bad_der, position);
        }
    }

    fn test_prop_deferred_verify_integration(chain: TestChain, input_payload: Bytes) {
        // Init the deferred payload verifier.
        let mut verifier = DeferredVerifierState::default();
        let hostname = EndpointHostname::try_from("leaf.itsallbroken.com".to_string()).unwrap();

        // And init a real verifier with the test root to ensure the two work
        // together:
        let trust_store = rc_x509_trust::trust_store::TrustStore::new(
            [chain.root()],
            MemoryCertCache::new(1024 * 1024),
        );

        // Generate a valid signature from this chain:
        let sig = chain.leaf.sign(&input_payload);

        //
        // There are no certificates in the local cache. Attempting a
        // verification will fail, and ask for the first cert in the chain.
        //
        // When that first cert is provided, verification will fail on the
        // second cert in the chain (from leaf to the root) and so on.
        //

        // Attempt to verify the payload with no certs cached, causing the
        // verification to be retained as a "deferred" validation:
        let err = verifier
            .verify_or_defer(
                &trust_store,
                &hostname,
                CORRELATION_ID,
                chain.leaf.cert().cert_id().to_owned(),
                sig.clone(),
                Payload::from(input_payload.clone()),
            )
            .expect_err("must fail due to missing cert");

        assert_matches!(err, VerifyFailure::MissingCert { deferred_count, missing_cert_id } => {
            // There must be exactly one deferred payload to verify.
            assert_eq!(deferred_count.get(), 1);

            // The error should be asking for the expected cert:
            assert_eq!(
                missing_cert_id.as_dangerous_comparable(),
                chain.leaf.cert().cert_id().as_dangerous_comparable(),
            );
        });

        // Add the leaf cert which allows the deferred verifications to be
        // resumed:
        let mut deferred = verifier
            .add_certs(
                &trust_store,
                vec![UntrustedCertBytes::new(chain.leaf.cert().as_der())],
            )
            .expect("adding valid cert bytes must succeed")
            .expect("pending deferred returned");

        // Now repeat the verification and observe that each intermediate from
        // leaf to root is asked for:

        for cert in chain.intermediates.iter().rev() {
            // There should be exactly one verification queued in the set of
            // deferred validations:
            let Deferred {
                correlation_id,
                signing_cert_id,
                signature,
                payload,
            } = deferred.next().expect("deferred entry returned");
            assert!(deferred.next().is_none());

            // Verify the inputs are not modified:
            assert_eq!(correlation_id, CORRELATION_ID);
            assert_eq!(
                signing_cert_id.as_dangerous_comparable(),
                chain.leaf.cert().cert_id().as_dangerous_comparable()
            );
            assert_eq!(signature, sig);
            assert_eq!(payload, Payload::from(input_payload.clone()));

            // Attempting to re-verify the payload without the intermediate
            // "cert" causes an error to be returned asking for "cert" to be
            // resolved.
            let err = verifier
                .verify_or_defer(
                    &trust_store,
                    &hostname,
                    correlation_id,
                    signing_cert_id,
                    signature,
                    payload,
                )
                .expect_err("must fail due to missing cert");

            assert_matches!(err, VerifyFailure::MissingCert { missing_cert_id, deferred_count } => {
                // The error should be asking for the expected cert:
                assert_eq!(
                    missing_cert_id.as_dangerous_comparable(),
                    cert.cert().cert_id().as_dangerous_comparable(),
                );

                // There must be exactly one deferred payload to verify.
                assert_eq!(deferred_count.get(), 1);
            });

            // Inserting this intermediate "cert" allows the verification to
            // succeed next step through the loop:
            deferred = verifier
                .add_certs(
                    &trust_store,
                    vec![UntrustedCertBytes::new(cert.cert().as_der())],
                )
                .expect("adding valid cert bytes must succeed")
                .expect("pending deferred returned");
        }

        // After asking for and having been given all the non-root certificates
        // in the chain, the final validation must succeed:
        let Deferred {
            correlation_id,
            signing_cert_id,
            signature,
            payload,
        } = deferred.next().expect("deferred entry returned");
        assert!(deferred.next().is_none());

        // Attempting to re-verify the payload without the intermediate
        // "cert" causes an error to be returned asking for "cert" to be
        // resolved.
        let payload = verifier
            .verify_or_defer(
                &trust_store,
                &hostname,
                correlation_id,
                signing_cert_id,
                signature,
                payload,
            )
            .expect("must succeed when all certs are known");

        assert_eq!(payload, Payload::from(input_payload));
    }

    fn test_prop_add_bad_certs(chain: TestChain, bad_der: Bytes, position: prop::sample::Index) {
        let mut verifier = DeferredVerifierState::default();

        // Build a batch of otherwise valid certificates.
        let mut certs = chain
            .intermediates
            .iter()
            .chain(std::iter::once(&chain.leaf))
            .map(|v| UntrustedCertBytes::new(v.cert().as_der()))
            .collect::<Vec<_>>();

        // And insert the bad DER input at an arbitrary position within it
        // (including the end of the batch).
        let idx = position.index(certs.len() + 1);
        certs.insert(idx, UntrustedCertBytes::new(bad_der));

        // The verify() mock is never invoked - the error must be returned
        // before any verification is attempted.
        let mock = MockVerifier::default();

        let err = verifier
            .add_certs(&mock, certs)
            .expect_err("bad DER input must be rejected");

        assert_matches!(
            *err,
            ProtocolError::CertPush(crate::codec::CertPushViolation::InvalidDer(_))
        );
    }
}
