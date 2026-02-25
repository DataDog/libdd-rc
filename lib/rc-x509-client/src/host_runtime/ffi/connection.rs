//! FFI functions to manage the lifecycle of connections to the RC backend.

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

use std::{
    ffi::{c_int, c_uchar, c_void},
    sync::{
        atomic::AtomicBool,
        mpsc::{self, Receiver, Sender},
    },
};

use super::Ctx;

/// Initialise a new client connection state.
///
///   * Called by: `host runtime`.
///   * Ownership: passes mutable reference of `conn` for the duration of the
///     call, and returns ownership of [`FFIConnection`].
///
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn rc_conn_new(ctx: *mut Ctx) -> *mut FFIConnection {
    unimplemented!()
}

/// Mark the connection as established.
///
/// The caller MUST have made a previous call to [`rc_set_send_callback`],
/// else this call will return an error and the connection will not be
/// marked as available internally.
///
///   * Called by: `host runtime`.
///   * Ownership: passes mutable reference of [`FFIConnection`] to client
///     library for the duration of the call.
///
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn rc_conn_connected(conn: *mut FFIConnection) {
    unimplemented!()
}

/// Mark the connection as closed.
///
/// The caller MUST NOT call [`rc_conn_recv()`] for this `conn` after this
/// call, but MAY subsequently call [`rc_conn_connected()`] for the same
/// `conn` to resume communication.
///
///   * Called by: `host runtime`.
///   * Ownership: passes mutable reference of [`FFIConnection`] to client
///     library for the duration of the call.
///
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn rc_conn_disconnected(conn: *mut FFIConnection) {
    unimplemented!()
}

/// Pass data received from the RC delivery backend for the `conn`
/// connection.
///
///   * Called by: `host runtime`.
///   * Ownership: passes shared reference of [`FFIConnection`] and `data`
///     to client library for the duration of the call.
///
/// NOTE: the host runtime retains ownership of `data` after this call, and
/// is responsible for freeing the memory backing it after this call
/// completes.
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn rc_conn_recv(
    conn: *const FFIConnection,
    data: *const u8,
    length: i32,
) -> RecvRet {
    unimplemented!()
}

/// Send `data` from the client library to the RC delivery backend over the
/// network [`FFIConnection`] the callback was registered to..
///
/// Passes a reference to a byte slice of `length` number of bytes that is valid
/// for the lifetime of the function call.
///
///   * Called by: `client library`.
///   * Ownership: passes shared reference to the `data` array to the host
///     runtime for the duration of the call.
///
/// NOTE: the client library retains ownership of `data` after this call, and it
/// may be freed or modified at any time after this function returns.
pub(super) type SendCb = unsafe extern "C" fn(data: *const u8, length: i32) -> SendRet;

/// Configure the callback used by the client library to request data be sent to
/// the RC backend.
///
/// This call MUST be made before the first call to [`rc_conn_connected()`] for
/// the same `conn`.
///
///   * Called by: `host runtime`.
///   * Ownership: passes mutable reference of `conn` for the duration of the
///     call.
///
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn rc_set_send_callback(mut conn: *mut FFIConnection, cb: SendCb) {
    unimplemented!()
}

/// Release the resources held by this `conn`.
///
///   * Called by: `host runtime`.
///   * Ownership: passes ownership of [`FFIConnection`] to client library.
///
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn rc_conn_free(conn: *mut FFIConnection) {
    unimplemented!()
}

/// Result of sending data to the RC delivery backend, returned by the host
/// runtime.
#[derive(Debug)]
#[repr(i32)]
pub(super) enum SendRet {
    Success = 0,
    Closed = 1,
    QueueFull = 2,

    Unknown = i32::MAX,
}

/// Result of pushing data received from the RC delivery backend into the
/// internal client library recv queue (returned by the client library).
#[derive(Debug)]
#[repr(i32)]
pub(super) enum RecvRet {
    /// The message was successfully passed.
    Success = 0,
    QueueFull = 1,
}

/// An [`FFIConnection`] brokers I/O between the client library and the FFI host
/// runtime, modelling a single connection to the RC backend.
///
/// One [`FFIConnection`] directly maps to one RC backend platform session,
/// where "session" is typically a single WebSocket connection.
///
/// The [`FFIConnection`] holds per-connection state, and is registered to a
/// [`Ctx`] by the host runtime. The connection to the RC backend is managed by
/// the host runtime, and connection lifecycle events are communicated to the
/// client library by calling FFI functions with the appropriate
/// [`FFIConnection`] handle.
///
/// This type is represented across the FFI boundary as an [opaque handle]; the
/// host runtime can reference the handle when making subsequent FFI functions,
/// but cannot interact with the internal fields.
///
/// [opaque handle]: https://interrupt.memfault.com/blog/opaque-pointers
#[derive(Debug)]
#[repr(Rust)] // Explicitly not exposing internals across FFI boundary.
pub(super) struct FFIConnection {
    /// Send `data` from the client library to the RC backend over the existing
    /// network connection managed by the host runtime.
    ///
    /// See [`SendCb`].
    send: Option<SendCb>,
}
