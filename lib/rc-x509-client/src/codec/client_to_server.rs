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
    connection::{GracefulDisconnectionCount, ReconnectionData, UngracefulDisconnectionCount},
    host_runtime::CorrelationId,
};

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
        #[cfg_attr(test, proptest(strategy = "crate::tests::arbitrary_bytes()"))]
        client_nonce: Bytes,
        /// Number of times the server has asked the client to reconnect.
        graceful: GracefulDisconnectionCount,
        /// Number of times the connection has been ungracefully broken.
        ungraceful: UngracefulDisconnectionCount,
        /// Opaque data previously set by the server, if any.
        reconnection_data: Option<ReconnectionData>,
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
                reconnection_data,
            } => Message::ClientHello(v1::ClientHello {
                graceful_disconnection_count: graceful.as_raw(),
                ungraceful_disconnection_count: ungraceful.as_raw(),
                nonce: client_nonce,
                reconnection_data: reconnection_data
                    .map(|v| v.as_bytes().clone())
                    .unwrap_or_default(),
            }),

            ClientToServer::Pong => Message::Pong(v1::Pong::default()),

            ClientToServer::DispatchResponse {
                correlation_id,
                result,
            } => Message::Dispatch(DispatchResponse {
                correlation_id: correlation_id.get(),
                result: Some(result),
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
