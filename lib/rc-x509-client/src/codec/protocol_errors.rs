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

use rc_x509_proto::protocol::v1::{
    self,
    client_protocol_error::{
        CertIdInvalidLength, DeserialisationFailed, DispatchBeforeHandshake,
        DispatchMissingSignature, HandshakeAckBeforeHello, HandshakeConnectionIdRejected,
        HandshakeDuplicateAck,
    },
};

use crate::host_runtime::CorrelationId;

/// Reasons the client reports a protocol error to the backend, terminating
/// the connection.
///
/// Each variant is encoded on the wire as its own message, so error-specific
/// context can be attached to a variant without affecting the others.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum ProtocolError {
    /// The server has sent a ClientHelloAck before the client has sent the
    /// ClientHello handshake message.
    HandshakeAckBeforeHello,

    /// The server has sent a ClientHelloAck after the client had previously
    /// marked the handshake as complete.
    HandshakeDuplicateAck,

    /// The connection ID proposed by the server cannot be verified to have
    /// been derived from the client nonce, and therefore cannot be trusted as
    /// unique for this client.
    HandshakeConnectionIdRejected,

    /// The protobuf wire representation could not be deserialised.
    ///
    /// This either means the wire data was corrupt when it reached the
    /// client library, or a message type was sent to the client that is not
    /// aware of a new addition (breaking protobuf change).
    ///
    /// The attached `String` is reported to the server as a deserialisation
    /// error message.
    DeserialisationFailed(String),

    /// A `CertId` was received with an invalid / out-of-bounds length.
    CertIdInvalidLength(usize),

    /// A dispatch request arrived before the handshake had completed.
    DispatchBeforeHandshake(CorrelationId),

    /// A dispatch request did not contain any signature.
    DispatchMissingSignature(CorrelationId),

    /// A certificate push from the server could not be processed.
    CertPush(CertPush),
}

/// The set of faults that can occur whilst processing a certificate push from
/// the server.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum CertPush {
    /// A pushed certificate was not parsable as DER.
    ///
    /// The attached `String` is reported to the server as a parse error
    /// message.
    InvalidDer(String),
}

impl From<ProtocolError> for v1::client_protocol_error::Error {
    fn from(reason: ProtocolError) -> Self {
        use rc_x509_proto::protocol::v1::client_protocol_error::Error;

        match reason {
            ProtocolError::HandshakeAckBeforeHello => {
                Error::HandshakeAckBeforeHello(HandshakeAckBeforeHello {})
            }
            ProtocolError::HandshakeDuplicateAck => {
                Error::HandshakeDuplicateAck(HandshakeDuplicateAck {})
            }
            ProtocolError::HandshakeConnectionIdRejected => {
                Error::HandshakeConnectionIdRejected(HandshakeConnectionIdRejected {})
            }
            ProtocolError::DeserialisationFailed(error_msg) => {
                Error::DeserialisationFailed(DeserialisationFailed { error_msg })
            }
            ProtocolError::CertIdInvalidLength(v) => {
                Error::CertIdInvalidLength(CertIdInvalidLength { got_len: v as u64 })
            }
            ProtocolError::DispatchBeforeHandshake(id) => {
                Error::DispatchBeforeHandshake(DispatchBeforeHandshake {
                    correlation_id: id.get(),
                })
            }
            ProtocolError::DispatchMissingSignature(id) => {
                Error::DispatchMissingSignature(DispatchMissingSignature {
                    correlation_id: id.get(),
                })
            }
            ProtocolError::CertPush(CertPush::InvalidDer(err)) => {
                Error::CertPush(v1::client_protocol_error::CertPush {
                    error: Some(v1::client_protocol_error::cert_push::Error::InvalidDer(
                        rc_x509_proto::protocol::v1::client_protocol_error::cert_push::InvalidDer {
                            error_msg: err,
                        },
                    )),
                })
            }
        }
    }
}
