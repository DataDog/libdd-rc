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

//! Integration tests for the client library.

#![allow(unused_crate_dependencies)] // Tests have false positives.

mod harness;

use std::time::Duration;

use assert_matches::assert_matches;
use rc_crypto::connection_id::UntrustedConnectionId;
use rc_x509_client::codec::{ClientToServer, ServerToClient};

use crate::harness::client::TestClient;

/// A simple test of the client lifecycle:
///
///   1. A client is initialised and entrypoint executed.
///   2. Connection events are delivered driving a connection into the active
///      state.
///   3. A PING is sent.
///   4. A PONG is received.
///   5. The library is gracefully stopped.
///
#[tokio::test]
async fn test_ping_pong() {
    harness::logging::init();

    let mut client = TestClient::default();
    let mut conn = client.new_connection().await;

    // The client always sends a HELLO first.
    let got = conn.recv().await;
    assert_matches!(got, ClientToServer::ClientHello { .. });

    // The server then sends a PING:
    conn.send(Ok(ServerToClient::Ping)).await;

    // And the client must respond with PONG.
    let got = conn.recv().await;
    assert_matches!(got, ClientToServer::Pong);

    // Signal the client library shutdown:
    client.shutdown().await;
}

/// Connect the client to the mock backend server and verify the ClientHello
/// values it sends.
#[tokio::test]
async fn test_handshake() {
    harness::logging::init();

    let mut client = TestClient::default();
    let mut conn = client.new_connection().await;

    let got = conn.recv().await;
    let version = assert_matches!(
        got,
        ClientToServer::ClientHello {
            client_nonce,
            graceful,
            ungraceful,
            last_closed_connection_duration,
            reconnection_data,
            version_info,
            app_name
        } => {
            assert_eq!(client_nonce.len(), 16);
            assert_eq!(graceful.as_raw(), 0);
            assert_eq!(ungraceful.as_raw(), 0);
            assert_eq!(last_closed_connection_duration.as_seconds(), 0);
            assert_eq!(reconnection_data, None);
            assert_eq!(app_name, "test");

            version_info
        }
    );

    assert_eq!(
        version.major(),
        env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap()
    );
    assert_eq!(
        version.minor(),
        env!("CARGO_PKG_VERSION_MINOR").parse().unwrap()
    );
    assert_eq!(
        version.patch(),
        env!("CARGO_PKG_VERSION_PATCH").parse().unwrap()
    );
    assert_eq!(
        version.pre().unwrap_or_default(),
        env!("CARGO_PKG_VERSION_PRE")
    );
    assert_eq!(version.commit(), Some(env!("BUILD_GIT_COMMIT_HASH")));

    conn.send(Ok(ServerToClient::ClientHelloAck {
        connection_id: UntrustedConnectionId::new(Default::default(), Default::default()),
    }))
    .await;

    client.shutdown().await;
}

/// Ensure instance statistics accumulate / are reported across connections.
#[tokio::test]
async fn test_connection_metrics() {
    harness::logging::init();

    const DELAY: Duration = Duration::from_secs(60);

    let mut client = TestClient::default();

    let mut conn = client.new_connection().await;
    let got = conn.recv().await;
    assert_matches!(
        got,
        ClientToServer::ClientHello {
            graceful,
            ungraceful,
            last_closed_connection_duration,
            ..
        } => {
            assert_eq!(graceful.as_raw(), 0);
            assert_eq!(ungraceful.as_raw(), 0);
            assert_eq!(last_closed_connection_duration.as_seconds(), 0);
        }
    );

    tokio::time::pause();
    tokio::time::advance(DELAY).await;
    tokio::time::resume();

    conn.close().await;

    let mut conn = client.new_connection().await;
    let got = conn.recv().await;
    assert_matches!(
        got,
        ClientToServer::ClientHello {
            graceful,
            ungraceful,
            last_closed_connection_duration,
            ..
        } => {
            assert_eq!(graceful.as_raw(), 0);
            assert_eq!(ungraceful.as_raw(), 0);
            assert!(last_closed_connection_duration.as_seconds() >= DELAY.as_secs());
        }
    );

    client.shutdown().await;
}
