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

use std::{sync::Arc, time::Duration};

use futures::{Stream, StreamExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use tokio::pin;

use crate::{
    AbortOnDrop, ShutdownSignal,
    connection::{ConnectionActor, ConnectionEvent, ConnectionUpdate},
    host_runtime::Connection,
    metrics::InstanceMetrics,
};

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
        let metrics = Arc::new(InstanceMetrics::default());

        info!(
            version = %env!("CARGO_PKG_VERSION"),
            commit = %metrics.version().commit().unwrap_or("unknown"),
            "starting rc-x509-client instance"
        );

        // Begin processing the connection events.
        let conn_events = AbortOnDrop::from(tokio::spawn(handle_connection_events(
            shutdown.clone(),
            conn_events,
            metrics,
        )));

        // Wait forever for the shutdown signal.
        shutdown.wait_for_shutdown().await;

        //
        // Graceful shutdown has begun.
        //

        info!("stopping rc-x509-client");

        // Wait for the connection event loop to complete, which internally
        // shuts down and waits for for the active connection to complete.
        if let Err(e) = conn_events.into_inner().await {
            error!(error=%e, "connection event loop panic");
        }

        info!("stopped rc-x509-client instance");
    }
}

/// Process the stream of connection state changes from the host application.
///
/// # Graceful Shutdown
///
/// `incoming` is closed to signal this function should close any existing
/// connections and exit.
async fn handle_connection_events<IO>(
    shutdown: ShutdownSignal,
    incoming: impl Stream<Item = ConnectionUpdate<IO>> + Send + Sync + 'static,
    metrics: Arc<InstanceMetrics>,
) where
    IO: Connection,
{
    debug!("starting connection event handler");

    // A single connection can be active at any one time.
    //
    // TODO: this assumes the host opens a single connection - this needs to be
    // enforced at the FFI API.
    let mut active_conn: Option<ActiveConn> = None;

    pin!(incoming);
    loop {
        let event = tokio::select! {
            v = incoming.next() => v,
            _ = shutdown.wait_for_shutdown() => {
                debug!("gracefully stopping connection event handler");
                if let Some(v) = active_conn.take() {
                    v.stop().await;
                }
                return;
            }
        };

        let event = match event {
            Some(v) => v,
            None => {
                debug!("connection event stream closed");
                if let Some(v) = active_conn.take() {
                    v.stop().await;
                }
                return;
            }
        };

        debug!(?event, "received connection lifecycle event");

        match event.into_event() {
            ConnectionEvent::Init => debug!("new connection registered"),
            ConnectionEvent::Connected(io, dispatch) => {
                let stop = shutdown.child_token();
                let conn = ConnectionActor::new(io, stop.clone(), dispatch, Arc::clone(&metrics));
                let task = tokio::spawn(conn.run());

                let old = active_conn.replace(ActiveConn { task, stop });
                if let Some(v) = old {
                    v.stop().await;
                }
            }
            ConnectionEvent::Disconnected => {
                if let Some(v) = active_conn.take() {
                    v.stop().await;
                }
            }
            ConnectionEvent::Release => debug!("connection released"),
        }
    }
}

/// A container that holds the active connection.
struct ActiveConn {
    task: tokio::task::JoinHandle<()>,
    stop: CancellationToken,
}

impl ActiveConn {
    /// Shutdown and wait for the connection control loop to exit.
    async fn stop(self) {
        info!("stopping connection");
        self.stop.cancel();

        debug!("waiting for connection stop");
        if let Err(e) = self.task.await {
            error!(error=%e, "connection shutdown failure");
            return;
        }

        debug!("connection shutdown complete");
    }
}
