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

use assert_matches::assert_matches;
use proptest::prelude::*;
use rc_crypto::{Signature, certificate::id::CertId};
use rc_x509_client::{
    Payload,
    codec::{DetachedSignature, DispatchViolation, ServerToClient},
};
use rc_x509_test_helpers::{rcgen::ExtendedKeyUsagePurpose, test_issuer::*};
use tokio_util::bytes::Bytes;

/// Generate `n_intermediates` and a random mutator seed, for mutators that
/// select which certificate in the chain to target.
fn arbitrary_seeded_chain(
    ca: &'static TestCA,
    n_intermediates: impl Strategy<Value = u8> + 'static,
    build: fn(&'static TestCA, u8, u8) -> TestChain,
) -> impl Strategy<Value = TestChain> {
    (n_intermediates, any::<u8>()).prop_map(move |(n, seed)| build(ca, n, seed))
}

/// Generate a chain that should always cause a fatal verification failure,
/// causing the client to return a protocol error.
pub(crate) fn arbitrary_fatal_chain_defect(
    ca: &'static TestCA,
    n_intermediates: impl Strategy<Value = u8> + Clone + 'static,
) -> impl Strategy<Value = TestChain> {
    prop_oneof![
        arbitrary_chain(ca, n_intermediates.clone(), CaSignerLeaf::default()),
        arbitrary_chain(
            ca,
            n_intermediates.clone(),
            CriticalExtensionLeaf::default()
        ),
        arbitrary_chain(ca, n_intermediates.clone(), ExpiredLeaf::default()),
        arbitrary_chain(ca, n_intermediates.clone(), ForgedLeaf::default()),
        arbitrary_chain(ca, n_intermediates.clone(), FutureValidLeaf::default()),
        arbitrary_chain(ca, n_intermediates.clone(), MismatchedLeafSan::default()),
        arbitrary_chain(ca, n_intermediates.clone(), OrphanLeaf::default()),
        arbitrary_chain(ca, n_intermediates.clone(), PathLenViolation::default()),
        arbitrary_chain(ca, n_intermediates.clone(), PreEpochLeaf::default()),
        arbitrary_chain(
            ca,
            n_intermediates.clone(),
            SelfReferentialCertIds::default()
        ),
        arbitrary_seeded_chain(ca, n_intermediates.clone(), |ca, n, seed| {
            TestChain::build(ca, n, &CriticalExtensionIntermediate::new(seed))
        }),
        arbitrary_seeded_chain(ca, n_intermediates.clone(), |ca, n, seed| {
            TestChain::build(ca, n, &ExpiredIntermediate::new(seed))
        }),
        arbitrary_seeded_chain(ca, n_intermediates.clone(), |ca, n, seed| {
            TestChain::build(ca, n, &ForgedIntermediate::new(seed))
        }),
        arbitrary_seeded_chain(ca, n_intermediates.clone(), |ca, n, seed| {
            TestChain::build(ca, n, &FutureValidIntermediate::new(seed))
        }),
        arbitrary_seeded_chain(ca, n_intermediates.clone(), |ca, n, seed| {
            TestChain::build(ca, n, &NonCaIntermediate::new(seed))
        }),
        arbitrary_seeded_chain(ca, n_intermediates.clone(), |ca, n, seed| {
            TestChain::build(ca, n, &PreEpochIntermediate::new(seed))
        }),
        (
            n_intermediates.clone(),
            arbitrary_eku_apply_to().prop_filter("select disallowed EKU policies", |ekus| {
                // A certificate role violates the policy when it declares a
                // non-empty EKU set that does not include codeSigning.
                let violates = |v: Box<dyn Iterator<Item = &ExtendedKeyUsagePurpose> + '_>| {
                    let v = v.collect::<Vec<_>>();
                    !v.is_empty() && !v.contains(&&ExtendedKeyUsagePurpose::CodeSigning)
                };
                violates(ekus.leaf()) || violates(ekus.intermediates())
            })
        )
            .prop_map(move |(n, ekus)| TestChain::build(ca, n, &SetEKUs::new(ekus))),
        arbitrary_chain(
            ca,
            n_intermediates.clone(),
            SetLeafSans::new(LeafSanScenario::Mismatching)
        ),
        arbitrary_chain(
            ca,
            n_intermediates.clone(),
            SetLeafSans::new(LeafSanScenario::MultipleWithoutMatch)
        ),
        arbitrary_chain(
            ca,
            n_intermediates,
            SetNameConstraints::new(NameConstraintScenario::Mismatching)
        ),
    ]
}

/// A defect applied to an otherwise valid [`ServerToClient::Dispatch`] request
/// that is unacceptable and fatal to the client connection.
#[derive(Debug, Clone)]
pub(crate) enum DispatchDefect {
    /// The request targets a different connection ID to the one agreed during
    /// the handshake.
    ConnectionIdMismatch,

    /// The request carries no [`DetachedSignature`].
    MissingSignature,

    /// The request carries a [`DetachedSignature`] with no signature bytes.
    EmptySignature,

    /// The signature exceeds the maximum signature length.
    OversizedSignature(Vec<u8>),

    /// The signer cert ID is outside of the valid cert ID length bounds.
    CertIdInvalidLength(Vec<u8>),

    /// The signature was modified after signing.
    CorruptSignature,

    /// The signature is replaced with arbitrary bytes.
    ArbitrarySignature(Vec<u8>),

    /// The payload was modified after signing.
    CorruptPayload,

    /// Additional bytes were appended to the payload after signing.
    ExtendedPayload(Vec<u8>),

    /// The payload is signed by the key of an intermediate, but claims to be
    /// signed by the leaf.
    WrongSignerKey { seed: u8 },

    /// The payload is signed by an intermediate CA certificate, and correctly
    /// names it as the signer.
    IntermediateSigner { seed: u8 },
}

impl DispatchDefect {
    /// Apply this defect to `msg`, a valid dispatch request signed by the
    /// `chain` leaf.
    ///
    /// # Panics
    ///
    /// Panics if `msg` is not a [`ServerToClient::Dispatch`], or `chain` has no
    /// intermediates.
    pub(crate) fn apply(&self, msg: &mut ServerToClient, chain: &TestChain) {
        let ServerToClient::Dispatch {
            connection_id,
            payload,
            detached_signature,
            ..
        } = msg
        else {
            panic!("defect must be applied to a dispatch request");
        };

        match self {
            Self::ConnectionIdMismatch => *connection_id = corrupt(connection_id),
            Self::MissingSignature => *detached_signature = None,
            Self::EmptySignature => signature_mut(detached_signature).signature = Bytes::new(),
            Self::OversizedSignature(v) | Self::ArbitrarySignature(v) => {
                signature_mut(detached_signature).signature = Bytes::copy_from_slice(v);
            }
            Self::CertIdInvalidLength(v) => {
                signature_mut(detached_signature).cert_id = Bytes::copy_from_slice(v);
            }
            Self::CorruptSignature => {
                let sig = signature_mut(detached_signature);
                sig.signature = corrupt(&sig.signature);
            }
            Self::CorruptPayload => *payload = Payload::from(corrupt(payload.as_bytes())),
            Self::ExtendedPayload(v) => {
                let mut extended = payload.as_bytes().to_vec();
                extended.extend_from_slice(v);
                *payload = Payload::from(extended);
            }
            Self::WrongSignerKey { seed } => {
                let signer = pick_intermediate(chain, *seed);
                signature_mut(detached_signature).signature =
                    Bytes::copy_from_slice(signer.sign(payload.as_bytes()).as_ref());
            }
            Self::IntermediateSigner { seed } => {
                let signer = pick_intermediate(chain, *seed);
                *detached_signature = Some(DetachedSignature {
                    cert_id: Bytes::copy_from_slice(
                        signer.cert().cert_id().as_dangerous_comparable().as_bytes(),
                    ),
                    signature: Bytes::copy_from_slice(signer.sign(payload.as_bytes()).as_ref()),
                });
            }
        }
    }

    /// Assert `got` is the violation this defect MUST cause.
    pub(crate) fn assert_violation(&self, got: DispatchViolation) {
        match self {
            Self::ConnectionIdMismatch => {
                assert_matches!(got, DispatchViolation::ConnectionIdMismatch)
            }
            Self::MissingSignature | Self::EmptySignature => {
                assert_matches!(got, DispatchViolation::MissingSignature)
            }
            Self::OversizedSignature(_) => {
                assert_matches!(got, DispatchViolation::MalformedSignature(_))
            }
            Self::CertIdInvalidLength(v) => {
                assert_eq!(got, DispatchViolation::CertIdInvalidLength(v.len()))
            }
            Self::CorruptSignature
            | Self::ArbitrarySignature(_)
            | Self::CorruptPayload
            | Self::ExtendedPayload(_)
            | Self::WrongSignerKey { .. } => {
                assert_matches!(got, DispatchViolation::SignatureMismatch)
            }
            Self::IntermediateSigner { .. } => {
                assert_matches!(got, DispatchViolation::VerifyChainFailed(_))
            }
        }
    }
}

/// Return a copy of `v` with the first byte changed.
fn corrupt(v: &Bytes) -> Bytes {
    let mut v = v.to_vec();
    v[0] = v[0].wrapping_add(1);
    Bytes::from(v)
}

fn signature_mut(v: &mut Option<DetachedSignature>) -> &mut DetachedSignature {
    v.as_mut().expect("valid dispatch request must be signed")
}

fn pick_intermediate(chain: &TestChain, seed: u8) -> &Identity {
    assert!(
        !chain.intermediates.is_empty(),
        "defect requires at least 1 intermediate"
    );
    &chain.intermediates[seed as usize % chain.intermediates.len()]
}

/// Generate a [`DispatchDefect`] that causes the client to raise a fatal
/// protocol error when applied to a valid dispatch request.
pub(crate) fn arbitrary_fatal_dispatch_defect() -> impl Strategy<Value = DispatchDefect> {
    prop_oneof![
        Just(DispatchDefect::ConnectionIdMismatch),
        Just(DispatchDefect::MissingSignature),
        Just(DispatchDefect::EmptySignature),
        prop::collection::vec(any::<u8>(), (Signature::MAX_LENGTH + 1)..=255)
            .prop_map(DispatchDefect::OversizedSignature),
        prop_oneof![
            prop::collection::vec(any::<u8>(), 0..CertId::MIN_LENGTH),
            prop::collection::vec(any::<u8>(), (CertId::MAX_LENGTH + 1)..=128),
        ]
        .prop_map(DispatchDefect::CertIdInvalidLength),
        Just(DispatchDefect::CorruptSignature),
        prop::collection::vec(any::<u8>(), 1..=Signature::MAX_LENGTH)
            .prop_map(DispatchDefect::ArbitrarySignature),
        Just(DispatchDefect::CorruptPayload),
        prop::collection::vec(any::<u8>(), 1..64).prop_map(DispatchDefect::ExtendedPayload),
        any::<u8>().prop_map(|seed| DispatchDefect::WrongSignerKey { seed }),
        any::<u8>().prop_map(|seed| DispatchDefect::IntermediateSigner { seed }),
    ]
}
