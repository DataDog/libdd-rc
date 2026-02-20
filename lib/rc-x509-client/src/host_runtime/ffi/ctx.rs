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

/// Initialise a new client [`Ctx`], starting a background thread to drive
/// internal execution.
///
///   * Called by: `host runtime`.
///   * Ownership: returns ownership of [`Ctx`] to host runtime.
///
#[unsafe(no_mangle)]
unsafe extern "C" fn rc_init() -> *mut Ctx {
    unimplemented!()
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
    unimplemented!()
}

/// A [`Ctx`] is a RAII handle for an instance of a X509 verifier.
///
/// The [`Ctx`] owns the event loop / runtime that drives the internal client
/// execution, and owns caches of state (certificates, CRLs, etc) which are
/// shared across all connections to the RC delivery backend.
///
/// Each [`Ctx`] can have zero or more [`FFIConnection`] registered to it to
/// provide I/O and manage per-connection state.
///
/// The FFI host is responsible for constructing a [`Ctx`] with [`rc_init()`],
/// and shutting down the [`Ctx`] with [`rc_free()`] to release all resources it
/// holds.
///
/// [`FFIConnection`]: super::FFIConnection
#[derive(Debug)]
pub struct Ctx {}
