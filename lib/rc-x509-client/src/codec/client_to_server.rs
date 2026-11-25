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

use rc_crypto::certificate::id::CertId;
use rc_x509_proto::{
    encode,
    protocol::v1::{self, DispatchResponse, client_to_server::Message},
};
use tokio_util::bytes::Bytes;

use crate::{
    app_info::{AppName, AppVersion},
    build_version::BuildVersion,
    codec::ProtocolError,
    connection::{
        GracefulDisconnectionCount, LastConnectedDuration, ReconnectionData,
        UngracefulDisconnectionCount,
    },
    host_runtime::CorrelationId,
};

/// All possible messages originating from this client library, sent to the RC
/// delivery backend.
#[derive(Debug, Clone)]
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
        /// A friendly name describing (and reported by) the host application.
        app_name: AppName,
        /// An opaque version string reported by the host application.
        app_version: AppVersion,
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

    /// Request the server push the certificate identified by `cert_id` (and
    /// optionally the chain to it) via a [`ServerToClient::CertificatePush`].
    ///
    /// [`ServerToClient::CertificatePush`]: super::ServerToClient::CertificatePush
    ChainFetch {
        /// The ID of the missing certificate.
        #[cfg_attr(test, proptest(strategy = "crate::tests::arbitrary_cert_id()"))]
        cert_id: CertId,
    },
}

/// Serialise this [`ClientToServer`] as a protobuf payload.
impl From<ClientToServer> for Bytes {
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
                app_version,
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
                app_name: app_name.to_string(),
                app_version: app_version.to_string(),
                metadata_snapshot: None,
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
            } => Message::ProtocolError(v1::ClientProtocolError {
                is_handshake_complete,
                error: Some(v1::client_protocol_error::Error::from(reason)),
            }),

            ClientToServer::ChainFetch { cert_id } => Message::ChainFetch(v1::ChainFetch {
                cert_id: Vec::from(cert_id).into(),
            }),
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

    /// Compare two [`ClientToServer`] for equality.
    ///
    /// [`ClientToServer`] cannot implement [`PartialEq`] as [`CertId`]
    /// intentionally does not implement it.
    fn messages_eq(a: &ClientToServer, b: &ClientToServer) -> bool {
        match (a, b) {
            (ClientToServer::Pong, ClientToServer::Pong) => true,
            (
                ClientToServer::ClientHello {
                    client_nonce: a_nonce,
                    graceful: a_graceful,
                    ungraceful: a_ungraceful,
                    last_closed_connection_duration: a_duration,
                    reconnection_data: a_reconnection,
                    version_info: a_version,
                    app_name: a_app_name,
                    app_version: a_app_version,
                },
                ClientToServer::ClientHello {
                    client_nonce: b_nonce,
                    graceful: b_graceful,
                    ungraceful: b_ungraceful,
                    last_closed_connection_duration: b_duration,
                    reconnection_data: b_reconnection,
                    version_info: b_version,
                    app_name: b_app_name,
                    app_version: b_app_version,
                },
            ) => {
                a_nonce == b_nonce
                    && a_graceful == b_graceful
                    && a_ungraceful == b_ungraceful
                    && a_duration == b_duration
                    && a_reconnection == b_reconnection
                    && a_version == b_version
                    && a_app_name == b_app_name
                    && a_app_version == b_app_version
            }
            (
                ClientToServer::DispatchResponse {
                    correlation_id: a_id,
                    result: a_result,
                },
                ClientToServer::DispatchResponse {
                    correlation_id: b_id,
                    result: b_result,
                },
            ) => a_id == b_id && a_result == b_result,
            (
                ClientToServer::ProtocolError {
                    reason: a_reason,
                    is_handshake_complete: a_complete,
                },
                ClientToServer::ProtocolError {
                    reason: b_reason,
                    is_handshake_complete: b_complete,
                },
            ) => a_reason == b_reason && a_complete == b_complete,
            (
                ClientToServer::ChainFetch { cert_id: a_id },
                ClientToServer::ChainFetch { cert_id: b_id },
            ) => a_id.as_dangerous_comparable() == b_id.as_dangerous_comparable(),
            (
                ClientToServer::Pong
                | ClientToServer::ClientHello { .. }
                | ClientToServer::DispatchResponse { .. }
                | ClientToServer::ProtocolError { .. }
                | ClientToServer::ChainFetch { .. },
                _,
            ) => false,
        }
    }

    proptest! {
        #[test]
        fn prop_message_serialisation(
            a in any::<ClientToServer>(),
            b in any::<ClientToServer>(),
        ) {
            let a_out = Bytes::from(a.clone());
            let b_out = Bytes::from(b.clone());

            // Invariant: deterministic serialisation.
            assert_eq!(a_out, Bytes::from(a.clone()));
            assert_eq!(b_out, Bytes::from(b.clone()));

            // Invariant: if the input message variants are equal (a == b) then
            // the output message variants are equal (a_out == b_out).
            assert_eq!(
                // If the input ClientToServer instances are the same.
                messages_eq(&a, &b),
                // Then the deterministic encoding must ensure the outputs are
                // both identical.
                a_out == b_out,
            );
        }
    }
}
