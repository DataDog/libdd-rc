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
    sync::atomic::AtomicBool,
};

use tokio::sync::mpsc;

use crate::connection::{ConnectionEvent, ConnectionId, ConnectionUpdate, IOHandle};

use super::Ctx;

/// Initialise a new client connection state.
///
///   * Called by: `host runtime`.
///   * Ownership: passes mutable reference of `conn` for the duration of the
///     call, and returns ownership of [`FFIConnection`].
///
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn rc_conn_new(ctx: *mut Ctx) -> *mut FFIConnection {
    assert!(!ctx.is_null());

    let conn = {
        let mut ctx = unsafe { &*ctx };
        ctx.new_connection()
    };

    Box::into_raw(conn)
}

/// Mark the connection as established.
///
/// The caller MUST have made a previous call to [`rc_conn_send_callback()`], else
/// this call will return an error and the connection will not be marked as
/// available internally.
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
pub(super) unsafe extern "C" fn rc_conn_send_callback(mut conn: *mut FFIConnection, cb: SendCb) {
    assert!(!conn.is_null());

    let mut conn = unsafe { &mut *conn };
    conn.set_send_callback(cb);
}

/// Release the resources held by this `conn`.
///
///   * Called by: `host runtime`.
///   * Ownership: passes ownership of [`FFIConnection`] to client library.
///
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn rc_conn_free(conn: *mut FFIConnection) {
    assert!(!conn.is_null());

    let mut conn = unsafe { Box::from_raw(conn) };

    conn.free()
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

/// The internal configuration state of a [`FFIConnection`].
///
/// ```text
///                          ┌──────────────┐
///                          │     Init     │
///                          └──────────────┘
///                                  │
///                                  ▼
///                          ┌──────────────┐
///                          │  Configured  │◀──┐
///                          └──────────────┘   │
///                                  │          │ Disconnect
///                                  ▼          │
///                          ┌──────────────┐   │
///                          │  Connected   │───┘
///                          └──────────────┘
/// ```
///
/// This type statically asserts the lifecycle of an FFI brokered connection by
/// requiring the `rc_init() -> rc_conn_send_callback() -> rc_conn_connected()`
/// progression in order to construct the [`State::Connected`] state.
#[derive(Debug)]
enum State {
    /// The connection has been initialised, but not yet configured or
    /// connected.
    Init,

    /// The connection is in a state where it can transition to
    /// [`State::Connected`].
    Configured {
        /// Send `data` from the client library to the RC backend over the existing
        /// network connection managed by the host runtime.
        ///
        /// See [`SendCb`].
        send: SendCb,
    },

    /// The connection is currently open to the RC backend.
    Connected { send: SendCb },
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
/// This type is expected to emit [`ConnectionEvent`] lifecycle updates.
///
/// [opaque handle]: https://interrupt.memfault.com/blog/opaque-pointers
#[derive(Debug)]
#[repr(Rust)] // Explicitly not exposing internals across FFI boundary.
pub(super) struct FFIConnection {
    id: ConnectionId,

    /// An event sink through which updates for this connection are published.
    events: mpsc::UnboundedSender<ConnectionUpdate<IOHandle>>,

    state: State,
}

#[allow(clippy::boxed_local)] // FFI init/free calls made through box only.
impl FFIConnection {
    pub(super) fn new(
        id: ConnectionId,
        events: mpsc::UnboundedSender<ConnectionUpdate<IOHandle>>,
    ) -> Box<Self> {
        let s = Self {
            id,
            events,
            state: State::Init,
        };

        // Publish that a new connection has been initialised.
        s.publish_event(ConnectionEvent::Init);

        Box::new(s)
    }

    /// A helper function to publish a [`ConnectionUpdate`] for this connection.
    fn publish_event(&self, event: ConnectionEvent<IOHandle>) {
        self.events.send(ConnectionUpdate::new(self.id, event));
    }

    /// Free this [`FFIConnection`] and emit a [`ConnectionEvent::Release`] to
    /// any event observers.
    fn free(self: Box<Self>) {
        match &self.state {
            State::Init | State::Configured { .. } => { /* allowed */ }
            State::Connected { .. } => {
                panic!("must disconnect connection before free")
            }
        }

        self.publish_event(ConnectionEvent::Release);
    }

    /// Set the [`SendCb`] for this [`FFIConnection`].
    ///
    /// # Panics
    ///
    /// This call panics if the connection is in use ([`State::Connected`]).
    fn set_send_callback(&mut self, cb: SendCb) {
        // Correctness: the callback can only be changed when the connection is
        // not in use (and therefore the caller has an exclusive ref).
        //
        // A callback MAY be changed after being set.
        match &self.state {
            State::Init | State::Configured { .. } => { /* allowed */ }
            State::Connected { .. } => {
                panic!("must disconnect connection before changing send callbacks")
            }
        }

        self.state = State::Configured { send: cb };
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use crate::host_runtime::ffi::{rc_free, rc_init};

    use super::*;

    fn is_send<T: Send>(t: T) {}
    fn static_assert_ctx_send(c: &mut FFIConnection) {
        is_send(c);
    }

    #[test]
    fn test_connection_init_free() {
        let ctx = unsafe { rc_init() };
        assert!(!ctx.is_null());

        let conn = unsafe { rc_conn_new(ctx) };
        assert!(!conn.is_null());
        assert_matches!(unsafe { &*conn }.state, State::Init);

        unsafe extern "C" fn do_send(data: *const u8, length: i32) -> SendRet {
            SendRet::Unknown
        }

        unsafe {
            rc_conn_send_callback(conn, do_send);
            assert_matches!((&*conn).state, State::Configured { send });
        }

        unsafe { rc_conn_free(conn) };
        unsafe { rc_free(ctx) };
    }
}
