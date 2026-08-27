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

use assert_matches::assert_matches;
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

    // The server sends a PING:
    conn.send(Ok(ServerToClient::Ping)).await;

    // And the client must respond with PONG.
    let got = conn.recv().await;
    assert_matches!(got, ClientToServer::Pong);

    // Signal the client library shutdown:
    client.shutdown().await;
}
