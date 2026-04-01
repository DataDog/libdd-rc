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

//! Client library executor handle for FFI callers.

use std::{
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
    thread::JoinHandle,
    time::Duration,
};

use tokio::{runtime::Handle, sync::mpsc};
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::{
    ShutdownCtl, ShutdownSignal,
    connection::{ConnectionEvent, ConnectionId, ConnectionUpdate, IOHandle},
    entrypoint::{GRACEFUL_SHUTDOWN_TIMEOUT, LibraryEntrypoint, Main},
    host_runtime::ffi::FFIConnection,
};

/// Initialise a new client [`Ctx`], starting a background thread to drive
/// internal execution.
///
///   * Called by: `host runtime`.
///   * Ownership: returns ownership of [`Ctx`] to host runtime.
///
/// # Safety
///
/// This call is always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_init() -> *mut Ctx {
    Box::into_raw(Ctx::new(Main::default()))
}

/// Stop the client running in [`Ctx`], and release all resources held by
/// [`Ctx`].
///
/// Callers MUST have previously disconnected ([`rc_conn_disconnected()`]) any
/// open connections and released ([`rc_conn_free()`]) any connections held by
/// the caller prior to calling this function.
///
///   * Called by: `host runtime`.
///   * Ownership: passes ownership of [`Ctx`] to client library.
///
/// # Safety
///
/// Must be called exactly once per `ctx` obtained from a prior call to
/// [`rc_init()`].
///
/// [`rc_conn_disconnected()`]: super::rc_conn_disconnected()
/// [`rc_conn_free()`]: super::rc_conn_free()
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_free(ctx: *mut Ctx) {
    assert!(!ctx.is_null());

    let mut ctx = unsafe { Box::from_raw(ctx) };

    ctx.shutdown()
}

/// A [`Ctx`] is a RAII handle for an instance of a X509 verifier.
///
/// The [`Ctx`] owns the event loop / runtime that drives the internal client
/// execution, and owns caches of state (certificates, CRLs, etc) which are
/// shared across all connections to the RC delivery backend.
///
/// Each [`Ctx`] spawns a worker thread, and can have zero or more
/// [`FFIConnection`] registered to it to provide I/O and manage per-connection
/// state.
///
/// The FFI host is responsible for constructing a [`Ctx`] with [`rc_init()`],
/// and shutting down the [`Ctx`] with [`rc_free()`] to release all resources it
/// holds.
///
/// [`FFIConnection`]: super::FFIConnection
#[derive(Debug)]
pub struct Ctx {
    /// An OS thread dedicated to driving an async runtime to execute
    /// [`crate::entrypoint()`] and all child tasks.
    runtime_thread: std::thread::JoinHandle<()>,

    /// A [`Handle`] to the async runtime, used to spawn tasks into the runtime
    /// for execution.
    runtime_handle: tokio::runtime::Handle,

    /// A shutdown signal for the [`crate::entrypoint()`] to gracefully stop all
    /// work and return within the [`GRACEFUL_SHUTDOWN_TIMEOUT`].
    shutdown: ShutdownCtl,

    /// The [`ConnectionId`] value that is assigned to the next call to
    /// [`Ctx::new_connection()`].
    next_connection_id: AtomicUsize,

    /// A sink through which [`ConnectionUpdate`] events are published.
    ///
    /// This publisher handle is shared with each [`FFIConnection`] constructed
    /// from this [`Ctx`].
    connection_events: mpsc::UnboundedSender<ConnectionUpdate<IOHandle>>,
}

#[allow(clippy::boxed_local)] // FFI init/free calls made through box only.
impl Ctx {
    /// Initialise a new [`Ctx`], typically called from [`rc_init()`].
    pub(crate) fn new<T>(main: T) -> Box<Self>
    where
        T: LibraryEntrypoint<IOHandle>,
    {
        let (signal, shutdown) = ShutdownSignal::new();

        // Initialise a channel through which connection lifecycle events will
        // be published to the non-FFI code.
        let (connection_events, conn_rx) = mpsc::unbounded_channel();

        // Channel to pass the runtime handle out of the dedicated runtime
        // thread, to the Ctx.
        let (handle_tx, handle_rx) = std::sync::mpsc::channel();

        // Spawn a background thread to drive the async runtime for this client
        // instance.
        let runtime_thread = std::thread::Builder::new()
            .name("rc-x509-worker".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .thread_name("rc-x509-runtime")
                    .thread_keep_alive(Duration::from_secs(60 * 60))
                    .build()
                    .expect("tokio runtime init for rc-x509-client");

                let handle = runtime.handle().clone();
                handle_tx.send(handle).expect("handle transfer tx");

                // Execute the client library "main" entrypoint function to
                // completion.
                runtime.block_on(main.entrypoint(signal, UnboundedReceiverStream::new(conn_rx)));

                // Allow spawned tasks to observe the shutdown signal and
                // perform cleanup before the runtime exits.
                runtime.shutdown_timeout(GRACEFUL_SHUTDOWN_TIMEOUT);
            })
            .expect("failed to spawn worker thread for rc-x509-client");

        // Obtain a handle to spawn tasks into the runtime.
        let runtime_handle = handle_rx.recv().expect("handle transfer rx");

        Box::new(Self {
            runtime_thread,
            runtime_handle,
            shutdown,
            next_connection_id: AtomicUsize::new(0),
            connection_events,
        })
    }

    /// Gracefully stop the library context, releasing all resources.
    ///
    /// Typically called from [`rc_free()`].
    pub(crate) fn shutdown(self: Box<Self>) {
        // Signal all tasks to stop.
        self.shutdown.shutdown_now();

        // Close the connection lifecycle events stream prior to blocking for
        // runtime cleanup.
        drop(self.connection_events);

        // Wait for the background runtime thread to finish.
        self.runtime_thread
            .join()
            .expect("rc-x509-client worker thread panic")
    }

    /// Initialise a new [`FFIConnection`] registered to this [`Ctx`].
    pub(super) fn new_connection(&self) -> Box<FFIConnection> {
        let id = ConnectionId::new(self.next_connection_id.fetch_add(1, Ordering::SeqCst));

        FFIConnection::new(
            self.runtime_handle.clone(),
            id,
            self.connection_events.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::atomic::fence, thread::yield_now};

    use assert_matches::assert_matches;
    use tokio::sync::oneshot;

    use super::*;

    const fn is_send<T: Send>() {}
    const _: () = is_send::<FFIConnection>();

    /// Test the lifecycle of the library [`Ctx`] through the FFI interface,
    /// ensuring it is correctly initialised and gracefully stopped.
    #[test]
    fn test_ffi_ctx_lifecycle() {
        let ctx = unsafe { rc_init() };
        assert!(!ctx.is_null());

        // Peek into the handle pointer to assert the runtime has been
        // established.
        {
            let inner = unsafe { ctx.as_mut() }.expect("non-null ref to ctx");

            assert!(!inner.runtime_thread.is_finished());
            assert_eq!(
                inner.runtime_thread.thread().name().expect("must be named"),
                "rc-x509-worker"
            );
        }

        // Do not be tempted to refactor the above explicit scope to use "inner"
        // later; it'll be UAF after the rc_free() call below.

        // Signal shutdown and block until complete.
        unsafe { rc_free(ctx) };
    }
}
