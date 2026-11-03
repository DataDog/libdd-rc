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

use rc_crypto::certificate::Certificate;
use rc_x509_roots::RootCertificate;
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};
use thiserror::Error;
use tracing::debug;
use valuable::Valuable;
use webpki::{
    ExtendedKeyUsageValidator, KeyPurposeId, KeyUsage, anchor_from_trusted_cert, aws_lc_rs,
};

use crate::{cert::UntrustedCert, chain::UntrustedChain, endpoint_hostname::EndpointHostname};

/// Signature algorithms that are accepted when validating the signatures within
/// a certificate.
static ALLOWED_SIGNATURE_ALGORITHMS: &[&dyn SignatureVerificationAlgorithm] = &[
    aws_lc_rs::ECDSA_P256_SHA256,
    aws_lc_rs::ECDSA_P256_SHA384,
    aws_lc_rs::ECDSA_P256_SHA512,
    aws_lc_rs::ECDSA_P384_SHA256,
    aws_lc_rs::ECDSA_P384_SHA384,
    aws_lc_rs::ECDSA_P384_SHA512,
    aws_lc_rs::ECDSA_P521_SHA256,
    aws_lc_rs::ECDSA_P521_SHA384,
    aws_lc_rs::ECDSA_P521_SHA512,
    aws_lc_rs::ED25519,
    aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
    aws_lc_rs::RSA_PKCS1_2048_8192_SHA384,
    aws_lc_rs::RSA_PKCS1_2048_8192_SHA512,
    aws_lc_rs::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    aws_lc_rs::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    aws_lc_rs::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    aws_lc_rs::RSA_PKCS1_3072_8192_SHA384,
];

/// codeSigning EKU OID (1.3.6.1.5.5.7.3.3) encoded as DER OID value bytes.
///
/// Ref: <https://oidref.com/1.3.6.1.5.5.7.3.3>
const EKU_CODE_SIGNING_BYTES: &[u8] = &[43, 6, 1, 5, 5, 7, 3, 3];
const EKU_CODE_SIGNING: KeyPurposeId<'static> = KeyPurposeId::new(EKU_CODE_SIGNING_BYTES);

/// Acceptance policies for Extended Key Usage (EKU) values.
///
/// Ref: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12>
#[derive(Debug, Clone, Copy)]
pub(crate) enum EKUPolicy {
    /// Require the leaf certificate to be valid for at least the `codeSigning`
    /// EKU.
    RequireCodeSigning,
}

impl ExtendedKeyUsageValidator for EKUPolicy {
    fn validate(&self, iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        match self {
            // When required, delegate to the webpki KeyUsage validator.
            //
            // `required_if_present` requires codeSigning when the EKU
            // extension exists, but allows certs that omit EKU entirely
            // (e.g. intermediates that don't constrain EKU).
            Self::RequireCodeSigning => {
                KeyUsage::required_if_present(EKU_CODE_SIGNING_BYTES).validate(iter)
            }
        }
    }
}

/// Failures to verify a certificate chain.
#[derive(Debug, Error)]
pub(crate) enum ChainVerifyError {
    /// The certificate is malformed in some way; the error within describes
    /// precisely the cause.
    #[error("a certificate is malformed: {0}")]
    CertMalformed(webpki::Error),

    /// A certificate in the chain carries a signature that does not verify
    /// under the public key of the certificate that claims to have issued it.
    ///
    /// The certificate parsed correctly and the signature algorithm is
    /// supported - the signature itself is simply wrong, which means the
    /// certificate has been tampered with, or forged.
    #[error("a certificate signature is invalid for the issuer public key")]
    CertSignatureInvalid,

    /// As [`Self::CertSignatureInvalid`], but for the signature over the CRL
    /// instead of a certificate.
    #[error("the CRL signature is invalid for the issuer public key")]
    CrlSignatureInvalid,

    /// The CRL is malformed in some way; the error within describes precisely
    /// the cause.
    #[error("the CRL is malformed: {0}")]
    CrlMalformed(webpki::Error),

    /// Verifying the chain hit an internal limit designed to mitigate malicious
    /// chains; this chain may or may not be valid.
    #[error("verifying the chain hit an internal limit: {0}")]
    ChainWalkLimits(webpki::Error),

    /// The signer certificate is also a CA, which is not an allowed chain
    /// configuration - only leaf certificates may sign payloads.
    #[error("the leaf signer certificate has CA:TRUE")]
    SignerIsCa,

    /// The chain contains a non-leaf certificate that does not have `CA:TRUE`
    /// in the certificate profile, meaning it is not allowed to issue
    /// certificates.
    #[error("a chain intermediate is not allowed to issue child certificates (missing CA:TRUE)")]
    IntermediateNotCa,

    /// A certificate that forms part of the chain being verified is expired,
    /// relative to the local clock.
    #[error(
        "a certificate is expired (current local epoch is {}, not_after={})", 
        .current.as_secs(),
        .not_after.as_secs(),
    )]
    CertExpired {
        current: UnixTime,
        not_after: UnixTime,
    },

    /// A certificate that forms part of the chain being verified is not yet
    /// valid, relative to the local clock.
    #[error(
        "a certificate has a validity in the future (current local epoch is {}, not_before={})", 
        .current.as_secs(),
        .not_before.as_secs(),
    )]
    CertFutureValidity {
        current: UnixTime,
        not_before: UnixTime,
    },

    /// A certificate that forms part of the chain being verified has been
    /// explicitly revoked / untrusted, and cannot be used for verification.
    #[error("a certificate in the verification chain is revoked")]
    CertRevoked,

    /// The CRL being used to check revocations has expired (relative to the
    /// local clock), and verifications cannot succeed until a new, valid CRL is
    /// obtained by the client.
    #[error(
        "the CRL has expired (current local epoch is {}, next_update={})", 
        .current.as_secs(),
        .next_update.as_secs(),
    )]
    CrlExpired {
        current: UnixTime,
        next_update: UnixTime,
    },

    /// The [`EndpointHostname`] was not found in the signer certificate SAN
    /// entries, violating the DC pin. The connected DC is not allowed to sign
    /// payloads for the provided [`EndpointHostname`].
    ///
    /// This is a chain configuration, or [`EndpointHostname`] issue.
    #[error("DNS entry for '{expected}' not found in signer certificate SANs ({cert:?})")]
    LeafNameMismatch { expected: String, cert: Vec<String> },

    /// The chain contains an issuer certificate with a `nameConstraint` that is
    /// violated by a certificate that appears after it in the chain.
    ///
    /// This is a chain configuration issue.
    #[error("a certificate in the verification chain violates an issuer name constraint")]
    ChainNameConstraint,

    /// The chain has violated an issuer's `pathlen` constraint.
    ///
    /// This is a chain configuration issue.
    #[error("chain violates the pathlen of a issuing certificates")]
    PathLen,

    /// The chain contains EKU constraints, which does not include the required
    /// EKUs (`codeSigning`).
    ///
    /// This is a chain configuration issue.
    #[error("required cert EKU was not found (want oids={:?}, got oids={:?}))", .required, .found)]
    RequiredEKU {
        required: KeyUsage,
        found: Vec<Vec<usize>>,
    },

    /// The [`UntrustedChain`] being verified is constructed by following the
    /// AKI -> SKI values to provide a candidate chain.
    ///
    /// However when verifying the chain, name checks are used to track chain
    /// delegations instead - the "Issuer" field of a child certificate must
    /// match the "Subject" field of the issuing parent certificate, up to the
    /// root (this is the correct RFC-defined mechanism).
    ///
    /// This error indicates that a chain built using AKI -> SKI values produced
    /// a chain that does not hold true when following the name chaining
    /// algorithm. In practice, this should never happen, and may be an
    /// indicator of compromise.
    #[error(
        "
        chain building using AKI/SKI succeeded but verifying the chain failed \
        when following the issuer / subject names\
    "
    )]
    ChainBuildingMismatch,

    /// An input is unsupported - the captured error contains more details.
    #[error("unsupported: {0}")]
    Unsupported(webpki::Error),

    /// A catch-all for unknown errors that may be returned by the webpki crate
    /// in the future.
    #[error("unknown error: {0}")]
    Unknown(webpki::Error),
}

impl From<webpki::Error> for ChainVerifyError {
    fn from(value: webpki::Error) -> Self {
        use webpki::Error;

        match value {
            // Malformed / unexpected inputs.
            v @ (Error::BadDer
            | Error::BadDerTime
            | Error::EmptyEkuExtension
            | Error::ExtensionValueInvalid
            | Error::InvalidCertValidity
            | Error::InvalidSerialNumber
            | Error::InvalidNetworkMaskConstraint
            | Error::MalformedDnsIdentifier
            | Error::MalformedExtensions
            | Error::MalformedNameConstraint
            | Error::SignatureAlgorithmMismatch
            | Error::TrailingData(..)) => Self::CertMalformed(v),

            // A failed signature check against the issuer public key.
            //
            // webpki re-maps `InvalidSignatureForPublicKey` to
            // `InvalidCrlSignatureForPublicKey` for all CRL signature checks,
            // so these two cases are unambiguous.
            Error::InvalidSignatureForPublicKey => Self::CertSignatureInvalid,
            Error::InvalidCrlSignatureForPublicKey => Self::CrlSignatureInvalid,

            v @ (Error::InvalidCrlNumber | Error::IssuerNotCrlSigner) => {
                Self::CrlMalformed(v)
            }

            v @ (Error::MaximumNameConstraintComparisonsExceeded
            | Error::MaximumPathBuildCallsExceeded
            | Error::MaximumPathDepthExceeded
            | Error::MaximumSignatureChecksExceeded) => Self::ChainWalkLimits(v),

            // Expiry.
            Error::CrlExpired { time, next_update } => Self::CrlExpired {
                current: time,
                next_update,
            },
            Error::CertExpired { time, not_after } => Self::CertExpired {
                current: time,
                not_after,
            },
            Error::CertNotValidYet { time, not_before } => Self::CertFutureValidity {
                current: time,
                not_before,
            },

            // Explicit revocation
            Error::CertRevoked => Self::CertRevoked,

            // The chain we resolved does not chain when using name matching.
            Error::UnknownIssuer => Self::ChainBuildingMismatch,

            // Misc
            Error::NameConstraintViolation => Self::ChainNameConstraint,
            Error::PathLenConstraintViolated => Self::PathLen,
            Error::CaUsedAsEndEntity => Self::SignerIsCa,
            Error::EndEntityUsedAsCa => Self::IntermediateNotCa,
            Error::CertNotValidForName(ctx) => Self::LeafNameMismatch {
                expected: ctx.expected.to_str().to_string(),
                cert: ctx.presented,
            },
            Error::RequiredEkuNotFoundContext(ctx) => Self::RequiredEKU {
                required: ctx.required,
                found: ctx.present,
            },

            // Unsupported
            v @ (Error::UnknownRevocationStatus | // OCSP
            Error::UnsupportedCertVersion |
            Error::UnsupportedCriticalExtension |
            Error::UnsupportedCrlIssuingDistributionPoint |
            Error::UnsupportedCrlVersion |
            Error::UnsupportedDeltaCrl |
            Error::UnsupportedIndirectCrl |
            Error::UnsupportedNameType |
            Error::UnsupportedRevocationReason |
            Error::UnsupportedRevocationReasonsPartitioning |
            Error::UnsupportedCrlSignatureAlgorithmContext(
                ..
            ) |
            Error::UnsupportedSignatureAlgorithmContext(
                ..
            ) |
            Error::UnsupportedCrlSignatureAlgorithmForPublicKeyContext(
                ..
            ) |
            Error::UnsupportedSignatureAlgorithmForPublicKeyContext(
                ..
            )) => Self::Unsupported(v),

            // Catch all to satisfy the non-exhaustive match requirement.
            v => Self::Unknown(v),
        }
    }
}

/// Attempt to verify the validity of `cert`, using the candidate `chain` to
/// `root`.
///
/// If it is proven that `cert` descends from `root` via a valid `chain`, the
/// trusted [`Certificate`] is returned. If trust cannot be established, the
/// [`UntrustedCert`] input is consumed.
///
/// Any (optional) name constraints (see [RFC 5280 § 4.2.1.10]) on the
/// intermediates are applied during verification to enforce any configured "DNS
/// pins" that tie the certificates / signatures of one DC to a DNS name,
/// preventing their reuse in other DCs.
///
/// The full chain is checked for validity against the current system clock.
///
/// [RFC 5280 § 4.2.1.10]:
///     https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
pub(crate) fn verify_chain(
    root: &RootCertificate,
    cert: UntrustedCert,
    chain: UntrustedChain,
    eku_policy: EKUPolicy,
    dns_name: &EndpointHostname,
) -> Result<Certificate, ChainVerifyError> {
    let leaf_cert = CertificateDer::from(cert.as_der_slice());

    let root_cert = CertificateDer::from(root.as_der_slice());
    let anchor = anchor_from_trusted_cert(&root_cert).expect("root is always valid");

    let intermediates = chain
        .as_slice()
        .iter()
        .map(|v| CertificateDer::from(v.as_der_slice()))
        .collect::<Vec<_>>();

    // Verify the validity of the candidate chain.
    let ee = webpki::EndEntityCert::try_from(&leaf_cert)?;
    let _path = ee.verify_for_usage(
        ALLOWED_SIGNATURE_ALGORITHMS,
        &[anchor],
        &intermediates,
        UnixTime::now(),
        eku_policy,
        None,
        None,
    )?;

    // Ensure any DNS name constraints on the intermediates (used to "pin" a
    // certificate to a DC) are valid for the leaf's DNS SAN value.
    ee.verify_is_valid_for_subject_name(dns_name.as_server_name())?;

    debug!(
        root = root.as_value(),
        leaf = cert.as_value(),
        intermediates = chain.as_value(),
        "accepted certificate as valid"
    );

    Ok(cert.into_trusted())
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use proptest::prelude::*;
    use rcgen::ExtendedKeyUsagePurpose;

    use crate::{
        chain::{build_unverified_chain_for, tests::arbitrary_invalid_chain},
        test_issuer::{
            CertBuilder, ChainEKUConfig, LEAF_ENDPOINT_HOSTNAME, LeafSanScenario,
            NameConstraintScenario, SetEKUs, SetNameConstraints, TestCA, TestChain, ValidChain,
            arbitrary_chain, arbitrary_eku_apply_to, arbitrary_leaf_san_scenario,
            arbitrary_name_constraint_scenario,
        },
        trust_store::{CertCache, MemoryCertCache, RootSet, tests::arbitrary_ordered_root_set},
    };

    use super::*;

    static CA: TestCA = TestCA::new();
    static CA2: TestCA = TestCA::new();

    /// The default leaf SAN used in [`TestChain::build`].
    const DEFAULT_LEAF_SAN: &str = "leaf.itsallbroken.com";

    #[test]
    #[cfg(feature = "fips")]
    fn test_all_algos_are_fips() {
        for v in ALLOWED_SIGNATURE_ALGORITHMS {
            assert!(v.fips());
        }
    }

    proptest! {
        /// Generate a random, valid chain with 0 to 5 intermediates between the
        /// root and the leaf.
        #[test]
        fn prop_valid_chain(
            roots in arbitrary_ordered_root_set(&CA, &CA2),
            input in arbitrary_chain(&CA, 0..=5_u8, ValidChain::default()),
        ) {
            test_prop_valid_chain(roots, input);
        }

        /// Generate an invalid chain, by applying a random ChainMutator, each
        /// of which manipulates the chain to produce an invalid input chain.
        #[test]
        fn prop_invalid_chain(
            roots in arbitrary_ordered_root_set(&CA, &CA2),
            input in arbitrary_invalid_chain(&CA, 2..=5_u8),
        ) {
            test_prop_invalid_chain(roots, input);
        }

        /// Randomise the set of EKUs on the chain certificates and assert:
        ///
        /// * [`EKUPolicy::RequireCodeSigning`] rejects a non-empty EKU set
        ///   that does not include codeSigning on any checked certificate.
        /// * [`EKUPolicy::RequireCodeSigning`] accepts any combination of EKUs
        ///   iff every certificate with an EKU extension includes codeSigning.
        ///
        #[test]
        fn prop_eku_policy(
            roots in arbitrary_ordered_root_set(&CA, &CA2),
            ekus in arbitrary_eku_apply_to(),
            n_intermediates in 0..=5_u8,
        ) {
            test_prop_eku_policy(roots, ekus, n_intermediates);
        }

        /// Randomise the name constraint configuration of intermediate
        /// certificates, and the dNSName SAN set of the leaf, and assert:
        ///
        /// * A chain is accepted when the intermediate name constraint permits
        ///   all leaf dNSName SANs and the DNS name input matches one of them.
        /// * A chain is rejected when an intermediate name constraint does NOT
        ///   permit a leaf dNSName SAN.
        /// * A chain is rejected when no leaf dNSName SAN matches the connected
        ///   endpoint.
        ///
        #[test]
        fn prop_dc_pin(
            roots in arbitrary_ordered_root_set(&CA, &CA2),
            connected_endpoint in prop_oneof![
                    Just("bananas.itsallbroken.com"),
                    Just(LEAF_ENDPOINT_HOSTNAME)
                ],
            ns_scenario in arbitrary_name_constraint_scenario(),
            san_scenario in arbitrary_leaf_san_scenario(),
            n_intermediates in 1..=5_u8, // Name constrains require an intermediate
        ) {
            test_prop_dc_pin(roots, connected_endpoint, ns_scenario, san_scenario, n_intermediates);
        }
    }

    /// Process a valid chain, expecting success.
    fn test_prop_valid_chain(roots: RootSet<2>, input: TestChain) {
        let cache = MemoryCertCache::new(1024 * 1024);

        // Populate the cache with all the intermediate certificates.
        for identity in &input.intermediates {
            cache.insert(UntrustedCert::from(identity.cert().clone()));
        }

        // Add a random extra intermediate that should not appear in the
        // resulting chain.
        cache.insert(UntrustedCert::from(
            CertBuilder::new_intermediate("Random Extra CA", CA.root())
                .allowed_domain("itsallbroken.com")
                .build()
                .cert()
                .clone(),
        ));

        // Build a chain that connects leaf to root.
        let chain = build_unverified_chain_for(
            &roots,
            &UntrustedCert::from(input.leaf.cert().clone()),
            &cache,
        )
        .expect("valid chain");

        let dns_name = EndpointHostname::try_from(DEFAULT_LEAF_SAN.to_owned()).unwrap();
        let got = verify_chain(
            &CA.root_cert(),
            UntrustedCert::from(input.leaf.cert().clone()),
            chain,
            EKUPolicy::RequireCodeSigning,
            &dns_name,
        )
        .expect("successfully validated chain");

        assert_eq!(got.fingerprint(), input.leaf.cert().fingerprint());
    }

    /// Process a chain with randomised EKUs, asserting the EKU policy
    /// properties.
    fn test_prop_eku_policy(roots: RootSet<2>, ekus: ChainEKUConfig, n_intermediates: u8) {
        // Generate the chain.
        let chain = TestChain::build(&CA, n_intermediates, &SetEKUs::new(ekus.clone()));

        // When there are no intermediates, intermediate EKU configs are never
        // applied to any certificate — normalise to match the effective state.
        let ekus = if n_intermediates == 0 {
            match ekus {
                ChainEKUConfig::IntermediatesOnly(_) => ChainEKUConfig::IntermediatesOnly(vec![]),
                ChainEKUConfig::IntermediatesAndLeaf { leaf, .. } => ChainEKUConfig::LeafOnly(leaf),
                other => other,
            }
        } else {
            ekus
        };

        // Populate the cache.
        let cache = MemoryCertCache::new(1024 * 1024);
        for identity in &chain.intermediates {
            cache.insert(UntrustedCert::from(identity.cert().clone()));
        }

        let root_cert = CA.root_cert();
        let untrusted_leaf = UntrustedCert::from(chain.leaf.cert().clone());

        // Build the candidate chain from the cache, which ignores EKUs.
        let candidate_chain = build_unverified_chain_for(&roots, &untrusted_leaf, &cache)
            .expect("valid chain structure");

        // Invariant 1 & 2: RequireCodeSigning requires the codeSigning EKU when
        // the EKU extension IS present, but allows certs that omit EKU entirely
        // (RFC 5280 § 4.2.1.12 states this means the cert is unconstrained).
        //
        // The chain is accepted iff each and EVERY certificate in the chain has
        // EITHER:
        //
        //   * A codeSigning EKU, or
        //   * No specified EKUs (empty set == unconstrained).
        //
        let dns_name = EndpointHostname::try_from(DEFAULT_LEAF_SAN.to_owned()).unwrap();
        let result = verify_chain(
            &root_cert,
            untrusted_leaf,
            candidate_chain,
            EKUPolicy::RequireCodeSigning,
            &dns_name,
        );

        // A helper to check if an EKU is codeSigning or not, used below.
        let is_codesign = |v: &ExtendedKeyUsagePurpose| *v == ExtendedKeyUsagePurpose::CodeSigning;
        let is_not_codesign =
            |v: &ExtendedKeyUsagePurpose| *v != ExtendedKeyUsagePurpose::CodeSigning;

        //
        // Assert the desired outcome for the specific random configuration.
        //

        // If all the certificates have no explicit EKU constrains, then they
        // are all unconstrained and should pass.
        if ekus.union().count() == 0 {
            assert_matches!(result, Ok(_));
            return;
        }

        // All options below this point involve an EKU constraint on some or all
        // of the chain.

        // If ALL parts of the chain contain the codeSigning EKU constraint, the
        // check passes.
        if ekus.leaf().any(is_codesign) && ekus.intermediates().any(is_codesign) {
            assert_matches!(result, Ok(_));
            return;
        }

        // If the codeSigning constraint is on the leaf only, then it is allowed
        // iff the intermediates are not constrained.
        if ekus.leaf().any(is_codesign) {
            if ekus.intermediates().count() == 0 {
                // Unconstrained intermediates.
                assert_matches!(result, Ok(_));
                return;
            }

            // Otherwise the intermediates are constrained without the
            // codeSigning EKU, because the "all certs have codeSigning" case
            // was checked earlier. Every certificate in the path must satisfy
            // the policy, so an intermediate that declares EKUs while omitting
            // codeSigning rejects the chain regardless of what the leaf says.
            assert!(ekus.intermediates().all(is_not_codesign)); // Test state assertion.
            assert_matches!(result, Err(ChainVerifyError::RequiredEKU { .. }));
            return;
        }

        // If the codeSigning constraint is on the intermediates only, then it
        // is allowed iff the leaf is not constrained.
        if ekus.intermediates().any(is_codesign) {
            if ekus.leaf().count() == 0 {
                // Unconstrained leaf.
                assert_matches!(result, Ok(_));
                return;
            }

            // Otherwise the leaf is constrained without the codeSigning EKU,
            // because the "all certs have codeSigning" case was checked
            // earlier. The leaf must satisfy the policy itself.
            assert!(ekus.leaf().all(is_not_codesign)); // Test state assertion.
            assert_matches!(result, Err(ChainVerifyError::RequiredEKU { .. }));
            return;
        }

        // Then the only remaining case is that either the leaf, or the
        // intermediate is constrained, but lacks a codeSigning EKU.
        if ekus.leaf().count() > 0 && ekus.leaf().all(is_not_codesign) {
            assert_matches!(result, Err(ChainVerifyError::RequiredEKU { .. }));
            return;
        }
        if ekus.intermediates().count() > 0 && ekus.intermediates().all(is_not_codesign) {
            assert_matches!(result, Err(ChainVerifyError::RequiredEKU { .. }));
            return;
        }

        unreachable!("all permutations are covered by checks above");
    }

    /// Assert the name constraint ("DC pin") and leaf SAN scenarios produce the
    /// expected outcome.
    fn test_prop_dc_pin(
        roots: RootSet<2>,
        connected_endpoint: &str,
        ns_scenario: NameConstraintScenario,
        san_scenario: LeafSanScenario,
        n_intermediates: u8,
    ) {
        let mutator =
            SetNameConstraints::new(ns_scenario.clone()).with_leaf_sans(san_scenario.clone());
        let chain = TestChain::build(&CA, n_intermediates, &mutator);

        let cache = MemoryCertCache::new(1024 * 1024);
        for identity in &chain.intermediates {
            cache.insert(UntrustedCert::from(identity.cert().clone()));
        }

        let candidate_chain = build_unverified_chain_for(
            &roots,
            &UntrustedCert::from(chain.leaf.cert().clone()),
            &cache,
        )
        .expect("valid chain structure");

        let dns_name = EndpointHostname::try_from(connected_endpoint.to_owned()).unwrap();
        let result = verify_chain(
            &CA.root_cert(),
            UntrustedCert::from(chain.leaf.cert().clone()),
            candidate_chain,
            EKUPolicy::RequireCodeSigning,
            &dns_name,
        );

        // Every leaf SAN must be permitted by the intermediate name
        // constraints, else the chain itself is invalid.
        if !san_scenario.sans().iter().all(|v| ns_scenario.permits(v)) {
            assert_matches!(
                result,
                Err(ChainVerifyError::ChainNameConstraint),
                "chain with mismatched name constraint must be rejected"
            );
            return;
        }

        // The chain configuration is valid, so the leaf must match the identity
        // of the endpoint the client connected to to succeed.
        if !san_scenario.sans().contains(&connected_endpoint) {
            assert_matches!(
                result,
                Err(ChainVerifyError::LeafNameMismatch { expected, cert }) => {
                    assert!(!cert.contains(&expected));
                    assert_eq!(expected, connected_endpoint);
                },
                "leaf that does not assert the connected endpoint must be rejected"
            );
            return;
        }

        result.expect("chain with valid name constraints and leaf SAN must be accepted");
    }

    /// Process an invalid chain, expecting an error.
    fn test_prop_invalid_chain(roots: RootSet<2>, input: TestChain) {
        let cache = MemoryCertCache::new(1024 * 1024);
        for identity in &input.intermediates {
            cache.insert(UntrustedCert::from(identity.cert().clone()));
        }

        let chain = build_unverified_chain_for(
            &roots,
            &UntrustedCert::from(input.leaf.cert().clone()),
            &cache,
        );

        let chain = match chain {
            Ok(v) => {
                // Building the unverified chain did not catch the changes.
                //
                // Continue below, where the chain is cryptographically
                // verified and MUST be identified as invalid.
                v
            }
            Err(_) => {
                // The chain was rejected at the first step, return early.
                return;
            }
        };

        let dns_name = EndpointHostname::try_from(DEFAULT_LEAF_SAN.to_owned()).unwrap();
        let err = verify_chain(
            &CA.root_cert(),
            UntrustedCert::from(input.leaf.cert().clone()),
            chain,
            EKUPolicy::RequireCodeSigning,
            &dns_name,
        )
        .expect_err("invalid chain must be rejected");

        // Each mutation maps onto a distinct rejection reason:
        //
        //   * ForgedLeaf / ForgedIntermediate -> CertSignatureInvalid
        //   * PathLenViolation -> PathLen
        //   * Expired{Leaf,Intermediate} -> CertExpired
        //   * FutureValid{Leaf,Intermediate} -> CertFutureValidity
        //
        assert_matches!(
            err,
            ChainVerifyError::CertSignatureInvalid
                | ChainVerifyError::PathLen
                | ChainVerifyError::CertExpired { .. }
                | ChainVerifyError::CertFutureValidity { .. }
        );
    }
}
