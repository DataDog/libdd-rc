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

#![no_main]

//! This fuzzer drives a series of arbitrary [`ServerToClient`] messages
//! directly into the connection actor.
//!
//! Run this fuzz with:
//!
//! ```shell
//! RUSTFLAGS="--cfg tracing_unstable" N=$(($(nproc)-1)) \
//!     cargo +nightly fuzz \
//!     run message_delivery -- \
//!     -print_final_stats=1 \
//!     -malloc_limit_mb=256 \
//!     -jobs=$N \
//!     -workers=$N
//! ```
//!
//! ## Fuzzing Coverage Optimisations
//!
//! * Generating the [`ServerToClient`] directly bypasses the protobuf
//!   deserialisation, allowing the fuzzer to explore client logic instead of
//!   the deserialisation code (which is covered in the `ffi_io` fuzz target).
//!
//! * Connection ID verification is disabled by enabling the "fuzzing" feature
//!   on [`rc_x509_client`]. The fuzzer will ~never generate the correct
//!   connection ID handshake response, so this is required for effective
//!   fuzzing.
//!

use std::{
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
    vec,
};

use futures::Stream;
use libfuzzer_sys::fuzz_target;
use rc_x509_client::{
    ShutdownSignal,
    codec::{ClientToServer, DecodingError, ServerToClient},
    connection::{ConnectionEvent, ConnectionUpdate},
    dispatch::new_dispatcher_interconnect,
    entrypoint::{LibraryEntrypoint, Main},
    host_runtime::{Connection, ConnectionErr},
};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;

fuzz_target!(|msgs: Vec<ServerToClient>| {
    runtime().block_on(run(msgs));
});

/// A async runtime used for repeated fuzz cases.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime construction")
    })
}

/// Initialise a connection actor via the [`Main::entrypoint()`], deliver `msgs`
/// to it, and then trigger a graceful shutdown once all messages have been
/// processed.
async fn run(msgs: Vec<ServerToClient>) {
    // This channel is closed by FuzzIO when the last message is read by the
    // actor.
    let (done_tx, done_rx) = oneshot::channel();

    // Initialise the FuzzIO which acts as a stream of incoming messages from
    // the server, closing the above channel once all messages have been read.
    let io = FuzzIO {
        from_server: Some(MessageStream {
            msgs: msgs.into_iter(),
            done: Some(done_tx),
        }),
    };

    let (shutdown, shutdown_ctl) = ShutdownSignal::new();
    let (events_tx, events_rx) = mpsc::channel(1);

    // Initialise the library entrypoint.
    let entrypoint = Main::new("rc-x509-client-fuzz".to_string(), "0.0.0".to_string());
    let driver = tokio::spawn(entrypoint.entrypoint(shutdown, ReceiverStream::new(events_rx)));

    // Init a dispatch interconnect, and keep it alive by holding onto all
    // handles.
    let (publisher, _dispatch_stream, _dispatch_responder) = new_dispatcher_interconnect();

    // Drive the initialisation of a connection actor.
    events_tx
        .send(ConnectionUpdate::new(ConnectionEvent::Connected(
            io, publisher,
        )))
        .await
        .expect("channel alive");

    // Wait until the actor has consumed and every message in `msgs`.
    done_rx
        .await
        .expect("connection actor must run to completion");

    // Trigger a graceful stop and block for it to complete.
    shutdown_ctl.shutdown_now();
    driver.await.expect("entrypoint task must not panic");
}

/// A [`Connection`] whose incoming stream is a fixed series of fuzzed
/// messages.
#[derive(Debug)]
struct FuzzIO {
    from_server: Option<MessageStream>,
}

impl Connection for FuzzIO {
    type Incoming = MessageStream;

    async fn send(&mut self, _payload: ClientToServer) -> Result<(), ConnectionErr> {
        Ok(())
    }

    fn take_recv_stream(&mut self) -> Option<Self::Incoming> {
        self.from_server.take()
    }
}

/// A [`Stream`] impl that yields each message, and then signals `done` the
/// first time it is polled again after exhausting `msgs`.
#[derive(Debug)]
struct MessageStream {
    msgs: vec::IntoIter<ServerToClient>,
    done: Option<oneshot::Sender<()>>,
}

impl Stream for MessageStream {
    type Item = Result<ServerToClient, DecodingError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(v) = this.msgs.next() {
            return Poll::Ready(Some(Ok(v)));
        }
        if let Some(done) = this.done.take() {
            let _ = done.send(());
        }
        Poll::Ready(None)
    }
}
