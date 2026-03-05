// Copyright 2026 Datadog, Inc
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

use crate::{AbortOnDrop, ShutdownSignal, connection::ConnectionUpdate, host_runtime::Connection};

pub(crate) const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Defines the library entrypoint that is invoked by the FFI host.
pub(crate) trait LibraryEntrypoint<IO>: std::fmt::Debug + Send + Sync + 'static {
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
    async fn entrypoint(
        self,
        shutdown: ShutdownSignal,
        conn_events: impl Stream<Item = ConnectionUpdate<IO>> + Send + Sync + 'static,
    );
}

/// The entrypoint for the non-FFI layer of the client library.
///
/// This struct exists to provide an indirection point / impl of
/// [`LibraryEntrypoint`] callable from the FFI layer.
#[derive(Debug, Default)]
pub(crate) struct Main;

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

        let _conn_events = AbortOnDrop::from(tokio::spawn(handle_connection_events(conn_events)));
        shutdown.wait_for_shutdown().await;

        info!("stopping rc-x509-client instance");
    }
}

async fn handle_connection_events<IO>(
    incoming: impl Stream<Item = ConnectionUpdate<IO>> + Send + Sync + 'static,
) where
    IO: std::fmt::Debug,
{
    debug!("starting connection event handler");
    pin!(incoming);

    while let Some(event) = incoming.next().await {
        debug!(?event, "received connection lifecycle event");
    }

    debug!("stopping connection event handler");
}
