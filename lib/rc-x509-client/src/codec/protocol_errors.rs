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

//! Codec for outgoing [`ClientToServer`] messages.
//!
//! [`ClientToServer`]: super::ClientToServer

use rc_x509_proto::protocol::v1::{self, client_protocol_error as proto};
use rc_x509_trust::chain::ChainVerifyError;
use thiserror::Error;

use crate::host_runtime::CorrelationId;

/// Reasons the client reports a protocol error to the backend, terminating
/// the connection.
///
/// Each variant is encoded on the wire as its own message, so error-specific
/// context can be attached to a variant without affecting the others.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum ProtocolError {
    /// The protobuf wire representation could not be deserialised.
    ///
    /// This either means the wire data was corrupt when it reached the
    /// client library, or a message type was sent to the client that is not
    /// aware of a new addition (breaking protobuf change).
    ///
    /// The attached `String` is reported to the server as a deserialisation
    /// error message.
    #[error("message deserialisation failed: {0}")]
    DeserialisationFailed(String),

    /// A fault occurred during the connection handshake.
    #[error("handshake error: {0}")]
    Handshake(#[from] HandshakeViolation),

    /// A dispatch request produced a fatal error.
    #[error("dispatch error for {0}: {1}")]
    Dispatch(CorrelationId, DispatchViolation),

    /// A certificate push from the server could not be processed.
    #[error("cert push error: {0}")]
    CertPush(#[from] CertPushViolation),
}

/// Protocol violations during the connection handshake.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum HandshakeViolation {
    /// The server has sent a ClientHelloAck before the client has sent the
    /// ClientHello handshake message.
    #[error("unexpected handshake ACK before client sent HELLO message")]
    AckBeforeHello,

    /// The server has sent a ClientHelloAck after the client had previously
    /// marked the handshake as complete.
    #[error("unexpected duplicate handshake ACK from server")]
    DuplicateAck,

    /// The connection ID proposed by the server cannot be verified to have
    /// been derived from the client nonce, and therefore cannot be trusted as
    /// unique for this client.
    #[error("handshake contained a connection ID that did not include client randomness")]
    ConnectionIdRejected,
}

/// The set of faults that can occur whilst processing a certificate push from
/// the server.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum CertPushViolation {
    /// A pushed certificate was not parsable as DER.
    ///
    /// The attached `String` is reported to the server as a parse error
    /// message.
    #[error("invalid DER bytes: {0}")]
    InvalidDer(String),
}

/// Protocol violations during dispatch request processing.
///
/// Each variant is scoped to the [`CorrelationId`] of the dispatch request
/// that caused it (see [`ProtocolError::Dispatch`]).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum DispatchViolation {
    /// A dispatch request arrived before the handshake had completed.
    ///
    /// This is suspicious, because the dispatch request requires the
    /// connection ID that is agreed as part of the handshake.
    #[error("received before handshake completion")]
    BeforeHandshake,

    /// A dispatch request did not contain any signature.
    #[error("missing signature")]
    MissingSignature,

    /// Verifying the certificate chain of the signer failed.
    #[error("chain verification failed: {0}")]
    VerifyChainFailed(VerifyChainFailed),

    /// Building a chain failed due to it exceeding the maximum length limit.
    #[error("excessively long chain for leaf")]
    ExcessivelyLongChain {
        /// The `CertId` of the leaf signer certificate used as the starting
        /// point of chain building.
        leaf_cert_id: Vec<u8>,
    },

    /// A `CertId` was received with an invalid / out-of-bounds length.
    #[error("certificate ID rejected with invalid length {0}")]
    CertIdInvalidLength(usize),

    /// A dispatch request included a malformed signature that could not be
    /// processed.
    #[error("malformed signature: {0}")]
    MalformedSignature(String),

    /// A valid chain was constructed and valid, but the signature did not
    /// match.
    ///
    /// This could be because:
    ///
    ///   * The signature was not produced by the signing cert indicated in the
    ///     dispatch request.
    ///
    ///   * The payload was modified after signing.
    ///
    #[error("signature does not match the signer certificate")]
    SignatureMismatch,
}

/// Chain verification failed for the chain described by the certificate IDs
/// within.
///
/// The `CertId` values are carried as raw bytes (and not as a
/// [`CertId`](rc_crypto::certificate::id::CertId)) as they are reported to the
/// server for diagnostics only, and are never compared or trusted by the
/// client.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[error("chain verify: {error}")]
pub struct VerifyChainFailed {
    /// The `CertId` of the root selected during chain building.
    pub root_cert_id: Vec<u8>,

    /// The `CertId` of each intermediate selected during chain building, in
    /// order from root to leaf.
    pub intermediate_cert_id: Vec<Vec<u8>>,

    /// The `CertId` of the leaf signer certificate used as the starting point
    /// of chain building.
    pub leaf_cert_id: Vec<u8>,

    /// The fault that caused verification of this chain to fail.
    pub error: ChainVerifyError,
}

impl From<ProtocolError> for v1::client_protocol_error::Error {
    fn from(reason: ProtocolError) -> Self {
        match reason {
            ProtocolError::DeserialisationFailed(error_msg) => {
                Self::DeserialisationFailed(proto::DeserialisationFailed { error_msg })
            }
            ProtocolError::Handshake(v) => Self::Handshake(proto::Handshake {
                error: Some(v.into()),
            }),
            ProtocolError::Dispatch(correlation_id, v) => Self::Dispatch(proto::Dispatch {
                correlation_id: correlation_id.get(),
                error: Some(v.into()),
            }),
            ProtocolError::CertPush(v) => Self::CertPush(proto::CertPush {
                error: Some(v.into()),
            }),
        }
    }
}

impl From<HandshakeViolation> for proto::handshake::Error {
    fn from(v: HandshakeViolation) -> Self {
        use proto::handshake;

        match v {
            HandshakeViolation::AckBeforeHello => {
                Self::AckBeforeHello(handshake::AckBeforeHello {})
            }
            HandshakeViolation::DuplicateAck => Self::DuplicateAck(handshake::DuplicateAck {}),
            HandshakeViolation::ConnectionIdRejected => {
                Self::ConnectionIdRejected(handshake::ConnectionIdRejected {})
            }
        }
    }
}

impl From<CertPushViolation> for proto::cert_push::Error {
    fn from(v: CertPushViolation) -> Self {
        match v {
            CertPushViolation::InvalidDer(error_msg) => {
                Self::InvalidDer(proto::cert_push::InvalidDer { error_msg })
            }
        }
    }
}

impl From<DispatchViolation> for proto::dispatch::Error {
    fn from(v: DispatchViolation) -> Self {
        use proto::dispatch;

        match v {
            DispatchViolation::BeforeHandshake => {
                Self::BeforeHandshake(dispatch::BeforeHandshake {})
            }
            DispatchViolation::MissingSignature => {
                Self::MissingSignature(dispatch::MissingSignature {})
            }
            DispatchViolation::VerifyChainFailed(v) => Self::VerifyChainFailed(v.into()),
            DispatchViolation::ExcessivelyLongChain { leaf_cert_id } => {
                Self::ExcessivelyLongChain(dispatch::ExcessivelyLongChain { leaf_cert_id })
            }
            DispatchViolation::CertIdInvalidLength(got_len) => {
                Self::CertIdInvalidLength(dispatch::CertIdInvalidLength {
                    got_len: got_len as u64,
                })
            }
            DispatchViolation::MalformedSignature(error) => {
                Self::MalformedSignature(dispatch::MalformedSignature { error })
            }
            DispatchViolation::SignatureMismatch => {
                Self::SignatureMismatch(dispatch::SignatureMismatch {})
            }
        }
    }
}

impl From<VerifyChainFailed> for proto::dispatch::VerifyChainFailed {
    fn from(v: VerifyChainFailed) -> Self {
        let VerifyChainFailed {
            root_cert_id,
            intermediate_cert_id,
            leaf_cert_id,
            error,
        } = v;

        Self {
            root_cert_id,
            intermediate_cert_id,
            leaf_cert_id,
            error: Some(chain_verify_error_to_wire(error)),
        }
    }
}

/// Map a [`ChainVerifyError`] - the source of truth for chain verification
/// failures - onto its wire representation.
///
/// This is a free function, and not a [`From`] implementation, as both types
/// are foreign to this crate.
fn chain_verify_error_to_wire(v: ChainVerifyError) -> proto::dispatch::verify_chain_failed::Error {
    use proto::dispatch::verify_chain_failed::{self as wire, Error};

    match v {
        ChainVerifyError::LeafNameMismatch { expected, cert } => {
            Error::LeafNameMismatch(wire::LeafNameMismatch { expected, cert })
        }
        ChainVerifyError::CertMalformed(e) => Error::CertMalformed(wire::CertMalformed {
            error_msg: e.to_string(),
        }),
        ChainVerifyError::CertSignatureInvalid => {
            Error::CertSignatureInvalid(wire::CertSignatureInvalid {})
        }
        ChainVerifyError::CrlSignatureInvalid => {
            Error::CrlSignatureInvalid(wire::CrlSignatureInvalid {})
        }
        ChainVerifyError::CrlMalformed(e) => Error::CrlMalformed(wire::CrlMalformed {
            error_msg: e.to_string(),
        }),
        ChainVerifyError::ChainWalkLimits(e) => Error::ChainWalkLimits(wire::ChainWalkLimits {
            error_msg: e.to_string(),
        }),
        ChainVerifyError::SignerIsCa => Error::SignerIsCa(wire::SignerIsCa {}),
        ChainVerifyError::IntermediateNotCa => Error::IntermediateNotCa(wire::IntermediateNotCa {}),
        ChainVerifyError::CertExpired { current, not_after } => {
            Error::CertExpired(wire::CertExpired {
                current: current.as_secs(),
                not_after: not_after.as_secs(),
            })
        }
        ChainVerifyError::CertFutureValidity {
            current,
            not_before,
        } => Error::CertFutureValidity(wire::CertFutureValidity {
            current: current.as_secs(),
            not_before: not_before.as_secs(),
        }),
        ChainVerifyError::CertRevoked => Error::CertRevoked(wire::CertRevoked {}),
        ChainVerifyError::CrlExpired {
            current,
            next_update,
        } => Error::CrlExpired(wire::CrlExpired {
            current: current.as_secs(),
            next_update: next_update.as_secs(),
        }),
        ChainVerifyError::ChainNameConstraint => {
            Error::ChainNameConstraint(wire::ChainNameConstraint {})
        }
        ChainVerifyError::PathLen => Error::PathLen(wire::PathLen {}),
        ChainVerifyError::RequiredEKU { required, found } => {
            Error::RequiredEku(wire::RequiredEku {
                required: format!("{required:?}"),
                found: found.iter().map(|oid| format!("{oid:?}")).collect(),
            })
        }
        ChainVerifyError::ChainBuildingMismatch => {
            Error::ChainBuildingFailure(wire::ChainBuildingFailure {})
        }
        ChainVerifyError::Unsupported(e) => Error::Unsupported(wire::Unsupported {
            error_msg: e.to_string(),
        }),
        ChainVerifyError::Unknown(e) => Error::Unknown(wire::Unknown {
            error_msg: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Assert the mapping of two different [`ChainVerifyError`] never map
        /// to the same wire value.
        #[test]
        fn prop_chain_verify_error_wire_mapping_is_injective(
            a in any::<ChainVerifyError>(),
            b in any::<ChainVerifyError>(),
        ) {
            use std::mem::discriminant;

            let same_input = discriminant(&a) == discriminant(&b);
            let same_output = discriminant(&chain_verify_error_to_wire(a))
                == discriminant(&chain_verify_error_to_wire(b));

            assert_eq!(same_input, same_output);
        }
    }
}
