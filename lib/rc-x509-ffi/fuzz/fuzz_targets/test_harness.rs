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

//! An internal test harness used to bypass the public API when fuzzing /
//! running benchmarks / etc.
//!
//! Only test code should depend on this module.
//!

// Conditionally re-exported.
#![allow(unreachable_pub)]

use futures::{Stream, StreamExt, pin_mut};

use rc_x509_client::{
    ShutdownSignal,
    codec::ClientToServer,
    connection::{ConnectionEvent, ConnectionUpdate},
    entrypoint::LibraryEntrypoint,
    host_runtime::Connection,
};

use crate::Ctx;

/// An [`EchoEntrypoint`] is designed to exercise the FFI layer, I/O handling
/// primitives, and runtime management in isolation.
///
/// This entrypoint watches for connection events, and then responds to any
/// incoming message delivered to it with a [`ClientToServer::Pong`]
/// irrespective of the incoming message. If the incoming message could not be
/// parsed a [`ClientToServer::Pong`] message is still returned as a heartbeat
/// signal.
#[derive(Debug)]
struct EchoEntrypoint;
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

/// Construct a [`Ctx`] that uses an [`EchoEntrypoint`] instead of the default
/// library entrypoint.
pub fn new_echo_ctx() -> Box<Ctx> {
    Ctx::new(EchoEntrypoint)
}
