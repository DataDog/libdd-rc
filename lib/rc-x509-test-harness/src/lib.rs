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

//! Test harness for Go FFI tests.

#![allow(unsafe_code)]

use futures::{Stream, StreamExt, pin_mut};
use rc_x509_client::{
    ShutdownSignal,
    codec::ClientToServer,
    connection::{ConnectionEvent, ConnectionUpdate},
    entrypoint::LibraryEntrypoint,
    host_runtime::Connection,
};

// Re-export everything from rc-x509-ffi
pub use rc_x509_ffi::*;

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
pub fn new_echo_ctx() -> Box<rc_x509_ffi::Ctx> {
    rc_x509_ffi::Ctx::new(EchoEntrypoint)
}

/// Initialise test [`Ctx`] with echo entrypoint for testing.
///
/// Echo entrypoint respond with Pong to all messages. Good for test FFI layer.
///
///   * Called by: `test code`.
///   * Ownership: returns ownership of [`Ctx`] to caller.
///
/// # Safety
///
/// This call is always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_init_test() -> *mut rc_x509_ffi::Ctx {
    Box::into_raw(new_echo_ctx())
}
