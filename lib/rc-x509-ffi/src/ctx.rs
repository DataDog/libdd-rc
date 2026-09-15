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

use std::{slice, str, time::Duration};

use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;

use rc_x509_client::{
    ShutdownCtl, ShutdownSignal,
    connection::ConnectionUpdate,
    entrypoint::{GRACEFUL_SHUTDOWN_TIMEOUT, LibraryEntrypoint, Main},
};

use crate::{DispatchCb, DispatchCbUserData, FFIConnection, io_handle::IOHandle};

/// Initialise a new client [`Ctx`], starting a background thread to drive
/// internal execution.
///
/// `app_name` and `version` identify the host application, and are reported
/// to the backend as part of the connection handshake.
///
///   * Called by: `host runtime`.
///   * Ownership: returns ownership of [`Ctx`] to host runtime. `app_name` and
///     `version` are copied into the returned [`Ctx`]; ownership of the
///     buffers backing them is retained by the caller.
///
/// # Safety
///
/// `app_name` MUST be valid for a read of `app_name_len` bytes, and `version`
/// MUST be valid for a read of `version_len` bytes, for the duration of this
/// function call. Both MUST reference valid UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_init(
    app_name: *const u8,
    app_name_len: u32,
    version: *const u8,
    version_len: u32,
) -> *mut Ctx {
    assert!(!app_name.is_null());
    assert!(!version.is_null());

    let app_name = unsafe { slice::from_raw_parts(app_name, app_name_len as usize) };
    let app_name = str::from_utf8(app_name)
        .expect("app_name must be valid UTF-8")
        .to_string();

    let version = unsafe { slice::from_raw_parts(version, version_len as usize) };
    let version = str::from_utf8(version)
        .expect("version must be valid UTF-8")
        .to_string();

    Box::into_raw(Ctx::new(Main::new(app_name, version)))
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

    let ctx = unsafe { Box::from_raw(ctx) };

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

    /// A sink through which [`ConnectionUpdate`] events are published.
    ///
    /// This publisher handle is shared with each [`FFIConnection`] constructed
    /// from this [`Ctx`].
    connection_events: mpsc::UnboundedSender<ConnectionUpdate<IOHandle>>,
}

#[allow(clippy::boxed_local)] // FFI init/free calls made through box only.
impl Ctx {
    /// Initialise a new [`Ctx`], typically called from [`rc_init()`].
    pub fn new<T>(main: T) -> Box<Self>
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
        let signal2 = signal.clone();
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
                runtime.block_on(main.entrypoint(signal2, UnboundedReceiverStream::new(conn_rx)));

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
    pub(super) fn new_connection(
        &self,
        dispatch: DispatchCb,
        dispatch_user_data: DispatchCbUserData,
    ) -> Box<FFIConnection> {
        FFIConnection::new(
            self.runtime_handle.clone(),
            self.connection_events.clone(),
            dispatch,
            dispatch_user_data,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn is_send<T: Send>() {}
    const _: () = is_send::<FFIConnection>();

    /// Test the lifecycle of the library [`Ctx`] through the FFI interface,
    /// ensuring it is correctly initialised and gracefully stopped.
    #[test]
    fn test_ffi_ctx_lifecycle() {
        let app_name = "test";
        let version = "0.0.0";
        let ctx = unsafe {
            rc_init(
                app_name.as_ptr(),
                app_name.len() as u32,
                version.as_ptr(),
                version.len() as u32,
            )
        };
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
