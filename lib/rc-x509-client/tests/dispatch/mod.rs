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

//! Tests specific to dispatch requests.
//!
//! This module is referenced from the top-level `integration.rs` file, instead
//! of being a file next to it, so that there's only one test binary to link
//! during test compilation, which speeds up the dev change / test cycle.

use assert_matches::assert_matches;
use rc_x509_client::{
    codec::{DetachedSignature, ServerToClient},
    host_runtime::CorrelationId,
};
use rc_x509_proto::{
    decode, encode,
    magic_tunnel::v1::{MagicTunnelRequest, Namespace},
    protocol::v1,
};
use tokio_util::bytes::Bytes;

use crate::harness::{
    self,
    client::{TestClient, conn_id_to_proto},
};

/// A test that exercises the client dispatch path and dispatch response path,
/// through a mocked host application.
#[tokio::test]
async fn test_dispatch_happy_path() {
    harness::logging::init();

    const APPLICATION_REQUEST_PAYLOAD: Bytes = Bytes::from_static(&[42, 42, 42, 42]);

    let mut client = TestClient::default();
    let mut conn = client.new_connection().await;

    // Perform the connection handshake to obtain the connection ID.
    let connection_id = conn_id_to_proto(conn.perform_handshake().await);

    // 1. The server sends a dispatch request:
    {
        let payload = Bytes::from_owner(encode(&v1::DispatchRequestPayload {
            connection_id: Some(connection_id.clone()),
            payload: Some(v1::dispatch_request_payload::Payload::MagicTunnel(
                MagicTunnelRequest {
                    namespace: Namespace::RemoteConfig as _,
                    payload: APPLICATION_REQUEST_PAYLOAD,
                },
            )),
        }));

        conn.send(Ok(ServerToClient::Dispatch {
            correlation_id: CorrelationId::new(42),
            payload,
            detached_signature: Some(DetachedSignature {
                cert_id: Bytes::from_static(&[42_u8; 16]),
                signature: vec![0, 0, 0, 0].into(),
            }),
        }))
        .await;
    }

    // 2. The application receives the application payload, tagged with the
    //    correct namespace for routing purposes:
    let _dispatch = {
        let dispatch = conn.get_application_dispatch().await;

        // The payload should emitted to the application includes metadata:
        let got: v1::DispatchRequestPayload = decode(dispatch.payload()).expect("valid message");

        // The connection ID must match.
        assert_matches!(got.connection_id, Some(id) => {
            assert_eq!(id, connection_id);
        });

        // The payload is specifically a magic tunnel request:
        let magic_tunnel_request = assert_matches!(
            got.payload,
            Some(v1::dispatch_request_payload::Payload::MagicTunnel(v)) => v
        );

        // And the namespace tag / payload bytes match:
        assert_eq!(magic_tunnel_request.namespace(), Namespace::RemoteConfig);
        assert_eq!(magic_tunnel_request.payload, APPLICATION_REQUEST_PAYLOAD);

        dispatch
    };

    // Signal the client library shutdown:
    client.shutdown().await;
}
