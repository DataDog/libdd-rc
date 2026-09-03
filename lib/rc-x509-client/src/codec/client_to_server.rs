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

use rc_x509_proto::{
    encode,
    protocol::v1::{self, DispatchResponse, client_to_server::Message},
};
use tokio_util::bytes::Bytes;

use crate::{
    build_version::BuildVersion,
    connection::{
        GracefulDisconnectionCount, LastConnectedDuration, ReconnectionData,
        UngracefulDisconnectionCount,
    },
    host_runtime::CorrelationId,
};

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
}

/// All possible messages originating from this client library, sent to the RC
/// delivery backend.
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum ClientToServer {
    /// A response to a [`ServerToClient::Ping`].
    ///
    /// [`ServerToClient::Ping`]: super::ServerToClient::Ping
    Pong,

    /// An opening handshake message sent at the start of a new connection.
    ClientHello {
        /// The client nonce used in the construction of a connection ID.
        #[cfg_attr(test, proptest(strategy = "crate::tests::arbitrary_bytes(0..1028)"))]
        client_nonce: Bytes,
        /// Number of times the server has asked the client to reconnect.
        graceful: GracefulDisconnectionCount,
        /// Number of times the connection has been ungracefully broken.
        ungraceful: UngracefulDisconnectionCount,
        /// Duration of time the most recently closed connection was active for.
        last_closed_connection_duration: LastConnectedDuration,
        /// Opaque data previously set by the server, if any.
        reconnection_data: Option<ReconnectionData>,
        /// Client build version.
        version_info: BuildVersion,
        /// A friendly name that describes the host application.
        app_name: String,
    },

    /// An async response to a [`ServerToClient::Dispatch`] request.
    ///
    /// [`ServerToClient::Dispatch`]: super::ServerToClient::Dispatch
    DispatchResponse {
        /// A unique ID to correlate this response with the request that
        /// generated this dispatch.
        correlation_id: CorrelationId,

        /// The response payload from the host application.
        result: v1::dispatch_response::Result,
    },

    /// The client reports a protocol error.
    ProtocolError {
        /// The violation code.
        reason: ProtocolError,

        /// A marker that is true if the connection that reports the violation
        /// has completed the handshake (from the client perspective).
        is_handshake_complete: bool,
    },
}

/// Serialise this [`ClientToServer`] as a protobuf payload.
impl From<ClientToServer> for Vec<u8> {
    fn from(value: ClientToServer) -> Self {
        // Construct the wire type for this `value`.
        let wire = match value {
            ClientToServer::ClientHello {
                client_nonce,
                graceful,
                ungraceful,
                last_closed_connection_duration: last_conn_duration,
                reconnection_data,
                version_info,
                app_name,
            } => Message::ClientHello(v1::ClientHello {
                graceful_disconnection_count: graceful.as_raw(),
                ungraceful_disconnection_count: ungraceful.as_raw(),
                last_closed_connection_duration_seconds: last_conn_duration.as_seconds(),
                nonce: client_nonce,
                reconnection_data: reconnection_data
                    .map(|v| v.as_bytes().clone())
                    .unwrap_or_default(),
                version_major: version_info.major(),
                version_minor: version_info.minor(),
                version_patch: version_info.patch(),
                version_commit: version_info.commit().map(|v| v.to_string()),
                version_pre: version_info.pre().map(|v| v.to_string()),
                app_name,
            }),

            ClientToServer::Pong => Message::Pong(v1::Pong::default()),

            ClientToServer::DispatchResponse {
                correlation_id,
                result,
            } => Message::Dispatch(DispatchResponse {
                correlation_id: correlation_id.get(),
                result: Some(result),
            }),
            ClientToServer::ProtocolError {
                reason,
                is_handshake_complete,
            } => {
                use rc_x509_proto::protocol::v1::client_protocol_error::*;

                let error = match reason {
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
                };

                Message::ProtocolError(v1::ClientProtocolError {
                    is_handshake_complete,
                    error: Some(error),
                })
            }
        };

        encode(&v1::ClientToServer {
            message: Some(wire),
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn prop_message_serialisation(
            a in any::<ClientToServer>(),
            b in any::<ClientToServer>(),
        ) {
            let a_out = Vec::from(a.clone());
            let b_out = Vec::from(b.clone());

            // Invariant: deterministic serialisation.
            assert_eq!(a_out, Vec::from(a.clone()));
            assert_eq!(b_out, Vec::from(b.clone()));

            // Invariant: if the input message variants are equal (a == b) then
            // the output message variants are equal (a_out == b_out).
            assert_eq!(
                // If the input ClientToServer instances are the same.
                a == b,
                // Then the deterministic encoding must ensure the outputs are
                // both identical.
                a_out == b_out,
            );
        }
    }
}
