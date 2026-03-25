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

//! The "main" of the client library.

use std::time::Duration;

use futures::{Stream, StreamExt};
use tracing::{debug, info};

use tokio::pin;

use crate::codec::{ClientToServer, ServerToClient};
use crate::connection::ConnectionEvent;
use crate::{ShutdownSignal, connection::ConnectionUpdate, host_runtime::Connection};

/// Time allotted to the [`LibraryEntrypoint`] for a graceful shutdown.
pub const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Defines the library entrypoint that is invoked by the FFI host.
pub trait LibraryEntrypoint<IO>: std::fmt::Debug + Send + Sync + 'static {
    /// The "main" function for an instance of the `rc-x509-client` library.
    ///
    /// # Graceful Shutdown
    ///
    /// When `shutdown` is signalled, work should cease and this function should
    /// complete within [`GRACEFUL_SHUTDOWN_TIMEOUT`] else they are killed at an
    /// arbitrary execution point.
    ///
    /// Additionally the `conn_events` channel will be closed, but the order w.r.t
    /// the shutdown signal is undefined.
    fn entrypoint(
        self,
        shutdown: ShutdownSignal,
        conn_events: impl Stream<Item = ConnectionUpdate<IO>> + Send + Sync + 'static,
    ) -> impl Future<Output = ()> + Send;
}

/// The entrypoint for the non-FFI layer of the client library.
///
/// This struct exists to provide an indirection point / impl of
/// [`LibraryEntrypoint`] callable from the FFI layer.
#[derive(Debug, Default)]
pub struct Main;

impl<IO> LibraryEntrypoint<IO> for Main
where
    IO: Connection,
{
    async fn entrypoint(
        self,
        shutdown: ShutdownSignal,
        conn_events: impl Stream<Item = ConnectionUpdate<IO>> + Send + Sync + 'static,
    ) {
        info!(
            version = env!("CARGO_PKG_VERSION"),
            "starting rc-x509-client instance"
        );

        tokio::select! {
            _ = handle_connection_events(conn_events) => {}
            _ = shutdown.wait_for_shutdown() => {}
        }

        info!("stopping rc-x509-client instance");
    }
}

async fn handle_connection_events<IO>(
    incoming: impl Stream<Item = ConnectionUpdate<IO>> + Send + Sync + 'static,
) where
    IO: Connection + std::fmt::Debug,
{
    debug!("starting connection event handler");
    pin!(incoming);

    let mut current_io: Option<IO> = None;
    let mut incoming_messages: Option<std::pin::Pin<Box<IO::Incoming>>> = None;

    loop {
        tokio::select! {
            Some(event) = incoming.next() => {
                debug!(?event, "received connection lifecycle event");

                let connection_id = event.id();
                match event.into_event() {
                    ConnectionEvent::Connected(mut io) => {
                        debug!(connection_id = ?connection_id, "connection established");

                        if let Some(stream) = io.take_recv_stream() {
                            incoming_messages = Some(Box::pin(stream));
                            current_io = Some(io);
                        }
                    }
                    ConnectionEvent::Disconnected => {
                        debug!("connection disconnected");
                        incoming_messages = None;
                        current_io = None;
                    }
                    _ => {}
                }
            }

            Some(message_result) = async {
                match &mut incoming_messages {
                    Some(stream) => stream.next().await,
                    None => None,
                }
            } => {
                match message_result {
                    Ok(ServerToClient::Ping) => {
                        debug!("received Ping, sending Pong");
                        if let Some(io) = &mut current_io
                            && let Err(e) = io.send(ClientToServer::Pong).await{
                            debug!(?e, "failed to send Pong response");
                            incoming_messages = None;
                            current_io = None;
                        }
                    }
                    Ok(ServerToClient::CertificatePush(_)) => {
                        debug!("received CertificatePush");
                    }
                    Err(e) => {
                        debug!(?e, "failed to decode incoming message");
                    }
                }
            }

            else => break
        }
    }

    debug!("stopping connection event handler");
}
