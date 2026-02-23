//! Client library executor handle for FFI callers.

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

use std::{ptr, thread::JoinHandle, time::Duration};

use tokio::runtime::Handle;

use crate::{GRACEFUL_SHUTDOWN_TIMEOUT, ShutdownCtl, ShutdownSignal, entrypoint::entrypoint};

/// Initialise a new client [`Ctx`], starting a background thread to drive
/// internal execution.
///
///   * Called by: `host runtime`.
///   * Ownership: returns ownership of [`Ctx`] to host runtime.
///
#[unsafe(no_mangle)]
unsafe extern "C" fn rc_init() -> *mut Ctx {
    Box::into_raw(Box::new(Ctx::new()))
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
/// [`rc_conn_disconnected()`]: super::rc_conn_disconnected()
/// [`rc_conn_free()`]: super::rc_conn_free()
#[unsafe(no_mangle)]
unsafe extern "C" fn rc_free(ctx: *mut Ctx) {
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
    runtime: std::thread::JoinHandle<()>,
    shutdown: ShutdownCtl,
}

impl Ctx {
    /// Initialise a new [`Ctx`], typically called from [`rc_init()`].
    pub(crate) fn new() -> Self {
        let (signal, shutdown) = ShutdownSignal::new();

        // Spawn a background thread to drive the async runtime for this client
        // instance.
        let runtime = std::thread::Builder::new()
            .name("rc-x509-worker".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .thread_name("rc-x509-runtime")
                    .build()
                    .expect("tokio runtime init for rc-x509-client");

                // Execute the client library "main" entrypoint function to
                // completion.
                runtime.block_on(entrypoint(signal));

                // Allow spawned tasks to observe the shutdown signal and
                // perform cleanup before the runtime exits.
                runtime.shutdown_timeout(GRACEFUL_SHUTDOWN_TIMEOUT);
            })
            .expect("failed to spawn worker thread for rc-x509-client");

        Self { runtime, shutdown }
    }

    /// Gracefully stop the library context, releasing all resources.
    ///
    /// Typically called from [`rc_free()`].
    pub(crate) fn shutdown(self) {
        // Signal all tasks to stop.
        self.shutdown.shutdown_now();

        // Wait for the background runtime thread to finish.
        self.runtime
            .join()
            .expect("rc-x509-client worker thread panic")
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::atomic::fence, thread::yield_now};

    use assert_matches::assert_matches;
    use futures::executor::block_on;
    use tokio::sync::oneshot;

    use super::*;

    fn is_send<T: Send>(t: T) {}
    fn static_assert_ctx_send(c: &mut Ctx) {
        is_send(c);
    }

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

            assert!(!inner.runtime.is_finished());
            assert_eq!(
                inner.runtime.thread().name().expect("must be named"),
                "rc-x509-worker"
            );
        }

        // Do not be tempted to refactor the above explicit scope to use "inner"
        // later; it'll be UAF after the rc_free() call below.

        // Signal shutdown and block until complete.
        unsafe { rc_free(ctx) };
    }
}
