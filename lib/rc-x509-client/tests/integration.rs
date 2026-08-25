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
use rc_x509_client::{
    ShutdownSignal,
    codec::{ClientToServer, ServerToClient},
    connection::{ConnectionEvent, ConnectionUpdate},
    dispatch::new_dispatcher_interconnect,
    entrypoint::{LibraryEntrypoint, Main},
};
use tokio::{sync::mpsc, time::timeout};
use tokio_stream::wrappers::ReceiverStream;

use crate::harness::io::new_io_pair;

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

    let (signal, stop) = ShutdownSignal::new();
    let (io, mut server) = new_io_pair();
    let (dispatch_publisher, _dispatch_stream, _dispatch_response) = new_dispatcher_interconnect();

    let client = Main::default();

    let (event_tx, event_rx) = mpsc::channel(1);
    let handle = tokio::spawn(client.entrypoint(signal, ReceiverStream::from(event_rx)));

    // Initialise the connection:
    event_tx
        .send(ConnectionUpdate::new(ConnectionEvent::Init))
        .await
        .unwrap();

    // And signal it is ready for I/O to begin:
    event_tx
        .send(ConnectionUpdate::new(ConnectionEvent::Connected(
            io,
            dispatch_publisher,
        )))
        .await
        .unwrap();

    // The server sends a PING:
    server
        .send(Ok(ServerToClient::Ping))
        .await
        .expect("must deliver");

    // And the client must respond with PONG.
    let got = server.recv().await.expect("must recv response");
    assert_matches!(got, ClientToServer::Pong);

    // Signal the client library shutdown:
    stop.shutdown_now();

    // And wait for the actor to stop:
    let _: () = timeout(Duration::from_secs(5), handle)
        .await
        .expect("graceful shutdown timeout")
        .expect("client panic");
}
