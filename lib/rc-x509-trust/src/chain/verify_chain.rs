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

use crate::{cert::UntrustedCert, chain::UntrustedChain};

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
            Self::RequireCodeSigning => {
                KeyUsage::required_if_present(EKU_CODE_SIGNING_BYTES).validate(iter)
            }
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum ChainVerifyError {
    #[error("failed to read leaf cert in chain")]
    ReadLeaf(webpki::Error),

    #[error("untrusted chain rejected: {0}")]
    RejectedChain(webpki::Error),
}

/// Attempt to verify the validity of `cert`, using the candidate `chain` to
/// `root`.
///
/// If it is proven that `cert` descends from `root` via `chain`, the trusted
/// [`Certificate`] is returned. If trust cannot be established, the
/// [`UntrustedCert`] input is consumed.
///
/// The full chain is checked for validity against the current system clock.
pub(crate) fn verify_chain(
    root: &RootCertificate,
    cert: UntrustedCert,
    chain: UntrustedChain,
    eku_policy: EKUPolicy,
) -> Result<Certificate, ChainVerifyError> {
    let leaf_cert = CertificateDer::from(cert.as_der_slice());

    let root_cert = CertificateDer::from(root.as_der_slice());
    let anchor = anchor_from_trusted_cert(&root_cert).expect("root is always valid");

    let intermediates = chain
        .as_slice()
        .iter()
        .map(|v| CertificateDer::from(v.as_der_slice()))
        .collect::<Vec<_>>();

    let ee = webpki::EndEntityCert::try_from(&leaf_cert).map_err(ChainVerifyError::ReadLeaf)?;
    let _path = ee
        .verify_for_usage(
            ALLOWED_SIGNATURE_ALGORITHMS,
            &[anchor],
            &intermediates,
            UnixTime::now(),
            eku_policy,
            None,
            None,
        )
        .map_err(ChainVerifyError::RejectedChain)?;

    debug!(
        root = root.as_value(),
        leaf = cert.as_value(),
        intermediates = chain.as_value(),
        "accepted certificate as valid"
    );

    // TODO(dom): verify subject name pin

    Ok(cert.into_trusted())
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use proptest::prelude::*;

    use crate::{
        chain::{build_unverified_chain_for, tests::arbitrary_invalid_chain},
        test_issuer::{CertBuilder, TestCA, TestChain, ValidChain, arbitrary_chain},
        trust_store::{CertCache, MemoryCertCache},
    };

    use super::*;

    static CA: TestCA = TestCA::new();

    #[test]
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
            input in arbitrary_chain(&CA, 0..=5_u8, ValidChain::default()),
        ) {
            test_prop_valid_chain(input);
        }

        /// Generate an invalid chain, by applying a random ChainMutator, each
        /// of which manipulates the chain to produce an invalid input chain.
        #[test]
        fn prop_invalid_chain(
            input in arbitrary_invalid_chain(&CA, 2..=5_u8),
        ) {
            test_prop_invalid_chain(input);
        }
    }

    /// Process a valid chain, expecting success.
    fn test_prop_valid_chain(input: TestChain) {
        let mut cache = MemoryCertCache::default();

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
            &RootCertificate::from_trusted_cert(input.root.cert().clone()),
            &UntrustedCert::from(input.leaf.cert().clone()),
            &cache,
        )
        .expect("valid chain");

        let got = verify_chain(
            &CA.root_cert(),
            UntrustedCert::from(input.leaf.cert().clone()),
            chain,
            EKUPolicy::RequireCodeSigning,
        )
        .expect("successfully validated chain");

        assert_eq!(got.fingerprint(), input.leaf.cert().fingerprint());
    }

    /// Process an invalid chain, expecting an error.
    fn test_prop_invalid_chain(input: TestChain) {
        let mut cache = MemoryCertCache::default();
        for identity in &input.intermediates {
            cache.insert(UntrustedCert::from(identity.cert().clone()));
        }

        let chain = build_unverified_chain_for(
            &RootCertificate::from_trusted_cert(input.root.cert().clone()),
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

        let err = verify_chain(
            &CA.root_cert(),
            UntrustedCert::from(input.leaf.cert().clone()),
            chain,
            EKUPolicy::RequireCodeSigning,
        )
        .expect_err("invalid chain must be rejected");

        assert_matches!(err, ChainVerifyError::RejectedChain(_));
    }
}
