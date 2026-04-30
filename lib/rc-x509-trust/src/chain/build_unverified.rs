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

use rc_crypto::certificate::id::IssuerCertId;
use thiserror::Error;
use tracing::{debug, error, warn};
use valuable::Valuable;

use crate::{
    cert::{RootCertificate, UntrustedCert},
    chain::UntrustedChain,
    trust_store::CertCache,
};

/// The absolute maximum allowed length of any chain from root to leaf,
/// including root and excluding leaf.
///
/// Chain lengths over this value will fail validation.
pub const MAX_CHAIN_LEN: usize = 20;

/// Errors during chain building.
#[derive(Debug, Error)]
pub enum ChainBuildError {
    /// An intermediate certificate is not in the local cache that is necessary
    /// for chain building to complete.
    #[error("intermediate certificate is missing from the trust store (cert ID: {0})")]
    MissingIntermediate(IssuerCertId),

    /// A chain was provided that has >= [`MAX_CHAIN_LEN`] number of
    /// certificates in the path from root to leaf.
    ///
    /// Chain building was aborted to avoid a potential DoS vector.
    #[error("refused to validate chain with >{MAX_CHAIN_LEN} nodes")]
    ExcessivelyLongChain,
}

/// Build a candidate chain from `cert` to `root`, using entries in `cache`.
///
/// The returned chain MUST be cryptographically verified before use.
///
/// All certificates necessary to build the chain must be present in `cache`, or
/// a [`ChainBuildError::MissingIntermediate`] error is returned.
///
/// ## Chain Building Logic
///
/// To build an unverified candidate chain, walk the trust chain backwards, from
/// the lead `cert` to the `root`, pushing intermediate certificates into
/// "chain", such that a trust chain such as this:
///
/// ```text
///                           ┌──────────────┐
///                           │   Root CA    │
///                           └──────────────┘
///                                   │
///                                   ▼
///                           ┌──────────────┐
///                           │   SubCA 1    │
///                           └──────────────┘
///                                   │
///                                   ▼
///                           ┌──────────────┐
///                           │   SubCA 2    │
///                           └──────────────┘
///                                   │
///                                   ▼
///                           ┌──────────────┐
///                           │     Leaf     │
///                           └──────────────┘
/// ```
///
/// Results in an unverified candidate "chain" vector laid out as:
///
/// ```text
///                 <leaf> -> [SubCA 2, SubCA 1] -> <root>
/// ```
///
/// Where `<leaf>` and `<cert>` are implicit and not present in the returned
/// chain - they must be passed into any subsequent calls that use the
/// [`UntrustedChain`].
pub(crate) fn build_unverified_chain_for<T>(
    root: &RootCertificate,
    cert: &UntrustedCert,
    cache: &T,
) -> Result<UntrustedChain, ChainBuildError>
where
    T: CertCache,
{
    let mut next_cert_id = cert.issuer_cert_id().to_owned();
    let mut chain = vec![];
    loop {
        // If the next cert ID to resolve is the same as the cert ID in the
        // root, the candidate chain is complete (but unverified).
        if next_cert_id.as_dangerous_comparable() == root.cert_id().as_dangerous_comparable() {
            break;
        }

        // Guard against a maliciously long chain that would result in
        // excessive memory / CPU utilisation by bounding the length of
        // "chain" and aborting if it his a threshold.
        if chain.len() > MAX_CHAIN_LEN {
            error!(
                cert = cert.as_value(),
                chain_len = %chain.len(),
                "rejecting excessively long chain for untrusted cert"
            );
            return Err(ChainBuildError::ExcessivelyLongChain);
        }

        let issuer_cert = match cache.get(next_cert_id.as_cert_id()) {
            Some(v) => {
                debug!(
                    issuer = v.as_value(),
                    for_cert_id = next_cert_id.as_value(),
                    "found issuer cert in local cache"
                );
                v
            }
            None => {
                warn!(
                    for_cert_id = next_cert_id.as_value(),
                    "no issuer cert in local cache"
                );
                return Err(ChainBuildError::MissingIntermediate(
                    next_cert_id.to_owned(),
                ));
            }
        };

        next_cert_id = issuer_cert.issuer_cert_id().to_owned();
        chain.push(issuer_cert);
    }

    Ok(UntrustedChain::from(chain))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use proptest::prelude::*;

    use crate::{
        test_issuer::{CertBuilder, Identity, TestCA},
        trust_store::MemoryCertCache,
    };

    use super::*;

    static CA: TestCA = TestCA::new();

    /// The root always chains to itself.
    #[test]
    fn test_root_chain_root() {
        let cache = MemoryCertCache::default();

        let got = build_unverified_chain_for(
            &CA.root_cert(),
            &UntrustedCert::from(CA.root().cert().clone()),
            &cache,
        )
        .expect("root chains to root");

        // There are no nodes in the path from root to root!
        assert!(got.as_slice().is_empty());
    }

    /// Ensure processing of excessively long chains is aborted and returns an
    /// error.
    #[test]
    fn test_excessively_long_chain_dos() {
        let mut cache = MemoryCertCache::default();

        // Generate a chain of N-1 intermediates in the cache.
        let mut last = None;
        for i in 0..=(MAX_CHAIN_LEN + 1) {
            let intermediate = CertBuilder::new_intermediate(
                format!("Intermediate {}", i + 1),
                last.as_ref().unwrap_or(CA.root()),
            )
            .allowed_domain("itsallbroken.com")
            .build();

            cache.insert(intermediate.cert().clone());
            last = Some(intermediate);
        }

        // And append the leaf.
        let leaf = CertBuilder::new_leaf("A Leaf Certificate", &last.unwrap())
            .san("leaf.itsallbroken.com")
            .build();

        let err = build_unverified_chain_for(
            &CA.root_cert(),
            &UntrustedCert::from(leaf.cert().clone()),
            &cache,
        )
        .expect_err("chain too long");

        assert_matches!(err, ChainBuildError::ExcessivelyLongChain);
    }

    #[derive(Debug)]
    struct TestChain {
        root: Arc<Identity>,
        intermediates: Vec<Identity>,
        leaf: Identity,
    }

    /// Generate a valid chain from the `CA` root, with `n_intermediates`
    /// between the root and leaf.
    fn arbitrary_valid_chain(
        n_intermediates: impl Strategy<Value = u8>,
    ) -> impl Strategy<Value = TestChain> {
        n_intermediates.prop_map(|n| {
            let mut intermediates = Vec::with_capacity(n as _);

            // Generate a chain of N-1 intermediates.
            for i in 0..n {
                let cert = CertBuilder::new_intermediate(
                    format!("Intermediate {}", i + 1),
                    intermediates.last().unwrap_or(CA.root()),
                )
                .allowed_domain("itsallbroken.com")
                .build();

                intermediates.push(cert);
            }

            // And append the leaf.
            let leaf = CertBuilder::new_leaf(
                "A Leaf Certificate",
                intermediates.last().unwrap_or(CA.root()),
            )
            .san("leaf.itsallbroken.com")
            .build();

            TestChain {
                root: Arc::clone(CA.root()),
                intermediates,
                leaf,
            }
        })
    }

    proptest! {
        /// Generate a random certificate chain, stuff it into the cache and
        /// perform a chain build. Assert the build returns the same chain as
        /// the input.
        #[test]
        fn prop_valid_chain_building(
            chain in arbitrary_valid_chain(0..5_u8),
        ) {
            let mut cache = MemoryCertCache::default();

            // Populate the cache with all the intermediate certificates.
            for identity in &chain.intermediates {
                cache.insert(identity.cert().clone());
            }

            // Add a random extra intermediate that should not appear in the
            // resulting chain.
            cache.insert(
                CertBuilder::new_intermediate("Random Extra CA", CA.root())
                    .allowed_domain("itsallbroken.com")
                    .build()
                    .cert()
                    .clone(),
            );

            // Build a chain that connects leaf to root.
            let got = build_unverified_chain_for(
                &RootCertificate::from_trusted_cert(chain.root.cert().clone()),
                &UntrustedCert::from(chain.leaf.cert().clone()),
                &cache,
            )
            .expect("valid chain");

            // Validate the returned chain matches the valid chain.
            //
            // Reverse the chain.intermediates which is ordered from root ->
            // leaf, but the output of build_unverified_chain() is from leaf ->
            // root.
            assert_eq!(got.as_slice().len(), chain.intermediates.len());
            for (got, input) in got.as_slice().iter().zip(chain.intermediates.iter().rev()) {
                assert_eq!(got.fingerprint(), input.cert().fingerprint());
            }
        }

        /// Build a chain with an intermediate missing, and assert an error
        /// identifying the missing certificate is returned.
        #[test]
        fn prop_missing_intermediate(
            chain in arbitrary_valid_chain(1..3_u8), // Always at least one intermediate
            i in 0..5, // Pick a random cert to drop.
        ) {
            let mut cache = MemoryCertCache::default();

            // Select a random element to drop.
            let drop_idx = i as usize % chain.intermediates.len();

            // Populate the cache but skip the drop_idx intermediate.
            for (i, identity) in chain.intermediates.iter().enumerate() {
                if i == drop_idx {
                    continue;
                }

                cache.insert(identity.cert().clone());
            }

            let err = build_unverified_chain_for(
                &RootCertificate::from_trusted_cert(chain.root.cert().clone()),
                &UntrustedCert::from(chain.leaf.cert().clone()),
                &cache,
            )
            .expect_err("invalid chain");

            // Ensure the error references the missing certificate ID.
            let issuer_id = assert_matches!(err, ChainBuildError::MissingIntermediate(id) => id);
            let dropped = chain.intermediates.get(drop_idx).unwrap();
            assert_eq!(
                dropped.cert().cert_id().as_dangerous_comparable(),
                issuer_id.as_dangerous_comparable()
            );
        }
    }
}
