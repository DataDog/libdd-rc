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

//! Test harness for FFI layer testing.
//!
//! Provides simple echo entrypoint for Go wrapper tests.

use futures::{Stream, StreamExt, pin_mut};

use rc_x509_client::{
    ShutdownSignal,
    codec::ClientToServer,
    connection::{ConnectionEvent, ConnectionUpdate},
    entrypoint::LibraryEntrypoint,
    host_runtime::Connection,
};

use crate::Ctx;

/// Echo entrypoint that respond to all messages with Pong.
///
/// This simple for test FFI layer and I/O without full RC protocol.
#[derive(Debug)]
pub struct EchoEntrypoint;

impl<IO> LibraryEntrypoint<IO> for EchoEntrypoint
where
    IO: Connection,
{
    async fn entrypoint(
        self,
        _shutdown: ShutdownSignal,
        conn_events: impl Stream<Item = ConnectionUpdate<IO>> + Send + Sync + 'static,
    ) {
        pin_mut!(conn_events);

        while let Some(event) = conn_events.next().await {
            if let ConnectionEvent::Connected(io) = event.into_event() {
                tokio::task::spawn(handle_conn(io));
            }
        }
    }
}

async fn handle_conn<IO>(mut io: IO)
where
    IO: Connection,
{
    let recv = io.take_recv_stream().expect("first use of connection I/O");
    pin_mut!(recv);

    while let Some(_v) = recv.next().await {
        io.send(ClientToServer::Pong)
            .await
            .expect("handle must be alive prior to shutdown");
    }
}

/// Make Ctx with echo entrypoint for tests.
pub fn new_echo_ctx() -> Box<Ctx> {
    Ctx::new(EchoEntrypoint)
}
