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
use rc_x509_client::host_runtime::CorrelationId;
use rc_x509_proto::magic_tunnel::v1::{Namespace, magic_tunnel_response};
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
    const APPLICATION_RESPONSE_PAYLOAD: Bytes = Bytes::from_static(&[13, 13, 13, 13]);

    let mut client = TestClient::default();
    let mut conn = client.new_connection().await;

    // Perform the connection handshake to obtain the connection ID.
    let connection_id = conn_id_to_proto(conn.perform_handshake().await);

    // 1. The server sends a dispatch request:
    conn.dispatch_magic_tunnel(
        CorrelationId::new(42),
        Namespace::RemoteConfig,
        APPLICATION_REQUEST_PAYLOAD,
    )
    .await;

    // 2. The application receives the application payload, tagged with the
    //    correct namespace for routing purposes:
    let dispatch = {
        let dispatch = conn.get_application_dispatch().await;

        // The payload must be routed for the correct connection, and be a
        // magic tunnel request tagged with the correct namespace / payload
        // bytes for routing purposes:
        let (namespace, payload) = dispatch.assume_magic_tunnel(&connection_id);
        assert_eq!(namespace, Namespace::RemoteConfig);
        assert_eq!(payload, APPLICATION_REQUEST_PAYLOAD);

        dispatch
    };

    let correlation_id = dispatch.correlation_id();

    // 3. The application generates a response:
    dispatch
        .respond_magic_tunnel(magic_tunnel_response::Result::Response(
            APPLICATION_RESPONSE_PAYLOAD.to_vec(),
        ))
        .await;

    // 4. The client must push the application's dispatch response to the
    //    server, correlated with the original request and carrying the
    //    application's response bytes:
    let result = conn
        .recv()
        .await
        .assume_magic_tunnel_response(correlation_id);
    let application_response = assert_matches!(
        result,
        magic_tunnel_response::Result::Response(v) => v
    );
    assert_eq!(application_response, APPLICATION_RESPONSE_PAYLOAD);

    // Signal the client library shutdown:
    client.shutdown().await;
}
