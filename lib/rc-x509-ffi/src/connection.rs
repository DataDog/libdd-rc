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

//! FFI functions to manage the lifecycle of connections to the RC backend.

use core::slice;
use std::ffi::c_void;

use futures::executor::block_on;
use tokio::{select, sync::mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use rc_x509_client::{
    AbortOnDrop,
    codec::{ClientToServer, DecodingError, ServerToClient},
    connection::{ConnectionEvent, ConnectionId, ConnectionUpdate},
};

use crate::io_handle::IOHandle;

use super::Ctx;

/// The number of payloads that can be enqueued in either direction
/// (independently) before returning errors.
const QUEUE_BUFFER_LEN: usize = 100;

/// Initialise a new client connection state.
///
///   * Called by: `host runtime`.
///   * Ownership: passes mutable reference of `conn` for the duration of the
///     call, and returns ownership of [`FFIConnection`].
///
/// # Safety
///
/// This call is safe iff `ctx` points to a handle obtained from a [`rc_init()`]
/// call that has not yet been freed, and is concurrency safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_conn_new(ctx: *const Ctx) -> *mut FFIConnection {
    assert!(!ctx.is_null());

    let conn = {
        let ctx = unsafe { &*ctx };
        ctx.new_connection()
    };

    Box::into_raw(conn)
}

/// Mark the connection as established.
///
/// The caller MUST have made a previous call to [`rc_conn_send_callback()`],
/// else this call will return an error and the connection will not be marked as
/// available internally.
///
///   * Called by: `host runtime`.
///   * Ownership: passes mutable reference of [`FFIConnection`] to client
///     library for the duration of the call.
///
/// # Safety
///
/// This call is not concurrency safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_conn_connected(conn: *mut FFIConnection) {
    assert!(!conn.is_null());

    let conn = unsafe { &mut *conn };
    conn.set_connected();
}

/// Mark the connection as closed.
///
/// The caller MUST NOT call [`rc_conn_recv()`] for this `conn` after this call,
/// but MAY subsequently call [`rc_conn_connected()`] for the same `conn` to
/// resume communication.
///
/// This call blocks until in-flight [`SendCb`] calls are completed and the
/// internal I/O task exists cleanly, after which time it is guaranteed no more
/// calls to the [`SendCb`] will be made.
///
///   * Called by: `host runtime`.
///   * Ownership: passes mutable reference of [`FFIConnection`] to client
///     library for the duration of the call.
///
/// # Safety
///
/// This call is not concurrency safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_conn_disconnected(conn: *mut FFIConnection) {
    assert!(!conn.is_null());

    let conn = unsafe { &mut *conn };
    conn.set_disconnected();
}

/// Pass data received from the RC delivery backend for the `conn` connection.
///
///   * Called by: `host runtime`.
///   * Ownership: passes shared reference of [`FFIConnection`] and `data` to
///     client library for the duration of the call.
///
/// NOTE: the host runtime retains ownership of `data` after this call, and is
/// responsible for freeing the memory backing it after this call completes.
///
/// # Safety
///
/// The `conn` MUST have previously been marked as ready using
/// [`rc_conn_connected()`], and the provided `data` MUST be valid for a read of
/// `length` bytes for the duration of this function call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_conn_recv(
    conn: *const FFIConnection,
    data: *const u8,
    length: u32,
) -> RecvRet {
    assert!(!conn.is_null());
    assert!(!data.is_null());

    if length == 0 {
        return RecvRet::Success;
    }

    // Build a slice from the raw pointer + length tuple.
    let payload = unsafe { slice::from_raw_parts(data, length as usize) };

    // Deserialise the byte buffer ref into an owned in-memory representation.
    //
    // This impl is guaranteed to copy all values from the source into the
    // destination struct (by Form<slice> impl); ownership of the "data" buffer
    // is retained by the caller.
    let message = ServerToClient::try_from(payload);

    // Call into the connection to enqueue the deserialised message (or
    // deserialisation error).
    let conn = unsafe { &*conn };
    conn.recv_incoming(message);

    RecvRet::Success
}

/// Send `data` from the client library to the RC delivery backend over the
/// network [`FFIConnection`] the callback was registered to..
///
/// Passes a reference to a byte slice of `length` number of bytes that is valid
/// for the lifetime of the function call.
///
/// The callback is invoked with the `user_data` value provided by the caller
/// when configuring the send callback.
///
///   * Called by: `client library`.
///   * Ownership: passes shared reference to the `data` array to the host
///     runtime for the duration of the call.
///
/// NOTE: the client library retains ownership of `data` after this call, and it
/// may be freed or modified at any time after this function returns.
pub type SendCb =
    unsafe extern "C" fn(data: *const u8, length: u32, user_data: *const c_void) -> SendRet;

/// Configure the callback used by the client library to request data be sent to
/// the RC backend.
///
/// This call MUST be made before the first call to [`rc_conn_connected()`] for
/// the same `conn`.
///
/// The `user_data` pointer is for use by the caller to pass state to the
/// subsequent [`SendCb`] calls, and is never referenced internally. It MAY be
/// null, but it MUST be safe to pass between threads.
///
///   * Called by: `host runtime`.
///   * Ownership: passes mutable reference of `conn` for the duration of the
///     call.
///
/// # Safety
///
/// This call MUST provide a `cb` that is valid and safe to call concurrently at
/// all times after [`rc_conn_connected()`] is called for `conn`, until a
/// subsequent [`rc_conn_disconnected()`] for the same `conn` returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_conn_send_callback(
    conn: *mut FFIConnection,
    cb: SendCb,
    user_data: *const c_void,
) {
    assert!(!conn.is_null());

    let conn = unsafe { &mut *conn };
    conn.set_send_callback(cb, SendCbUserData(user_data));
}

/// Release the resources held by this `conn`.
///
///   * Called by: `host runtime`.
///   * Ownership: passes ownership of [`FFIConnection`] to client library.
///
/// # Safety
///
/// The `conn` MUST be marked as disconnected ([`rc_conn_disconnected()`]) prior
/// to freeing the connection.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_conn_free(conn: *mut FFIConnection) {
    assert!(!conn.is_null());

    let conn = unsafe { Box::from_raw(conn) };

    conn.free()
}

/// Result of sending data to the RC delivery backend, returned by the host
/// runtime.
#[derive(Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum SendRet {
    /// The FFI host accepted this request.
    Success = 0,

    /// The connection is closed on the FFI side.
    Closed = 1,

    /// An unknown error occurred.
    Unknown = i32::MAX,
}

/// Result of pushing data received from the RC delivery backend into the
/// internal client library recv queue (returned by the client library).
#[derive(Debug, PartialEq)]
#[repr(i32)]
pub enum RecvRet {
    /// The message was successfully passed.
    Success = 0,
}

/// A container to hold the callback context pointer for a [`SendCb`] call.
///
/// NOTE: the pointer MAY be null and MUST never be dereferenced or modified.
#[derive(Debug, Clone, Copy)]
struct SendCbUserData(*const c_void);

// Safety: caller guarantees the pointer can be sent between threads. This
// pointer is never dereferenced by this library.
unsafe impl Send for SendCbUserData {}

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
        /// A FFI host provided callback.
        ///
        /// Safety: this callback should be considered invalid before a call to
        /// [`rc_conn_connected()`] and after a call to
        /// [`rc_conn_disconnected()`] by the FFI host to indicate it is safe to
        /// use.
        send: SendCb,
        user_data: SendCbUserData,
    },

    /// The connection is currently open to the RC backend.
    Connected {
        /// Send `data` from the client library to the RC backend over the
        /// existing network connection managed by the host runtime.
        ///
        /// See [`SendCb`].
        ///
        /// Safety: this callback MAY be used in this [`State`], as the FFI host
        /// has explicitly indicated it can be used by calling
        /// [`rc_conn_connected()`].
        send: SendCb,
        user_data: SendCbUserData,

        /// The channel through which the FFI [`rc_conn_recv()`] callback
        /// publishes incoming payloads from the RC backend.
        ffi2lib: mpsc::Sender<Result<ServerToClient, DecodingError>>,

        /// A task running in a dedicated OS thread, passing outgoing payloads
        /// through the FFI boundary to the FFI host to send to the RC backend.
        io_task: AbortOnDrop<()>,

        /// A signal to stop the io_task.
        io_task_stop: CancellationToken,
    },
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
/// # Handling I/O
///
/// Once the [`FFIConnection`] is in the [`State::Connected`] state, it can be
/// used to send outgoing I/O from the library, to the RC backend, and deliver
/// incoming payloads from the RC backend to the library.
///
/// All I/O is handled through an [`IOHandle`] presented to the non-FFI library
/// code as a safe, decoupled interface. Each [`FFIConnection`] runs an
/// [`io_task`] when in the [`State::Connected`] state to handle outgoing
/// payloads.
///
/// Outgoing I/O:
///
/// ```text
///                               libdd-rc
///                                  │
///                                  ▼
///                              IOHandle::send()
///                                  │
///                                  ▼
///                              lib2ffi channel
///                                  |
///                                  │       io_task pulls from the
///                                  ▼       lib2ffi & calls SendCb
///                                SendCb
///                                  │
///                                  ▼
///                            FFI Host Runtime
///                                  │
///                                  ▼
///                            RC Backend Server
/// ```
///
///   1. A call to [`IOHandle::send()`] is made, and the payload is added to an
///      internal FIFO queue.
///   2. Asynchronously the [`io_task`] assigned to this [`FFIConnection`] wakes
///      up, and pulls the payload from the queue.
///   3. The [`io_task`] calls the [`SendCb`] registered to the
///      [`FFIConnection`], invoking the callback on the FFI host.
///   4. The [`io_task`] frees the memory held by the payload.
///
/// Incoming I/O:
///
/// ```text
///                            RC Backend Server
///                                  │
///                                  ▼
///                            FFI Host Runtime
///                                  │
///                                  │ rc_conn_recv()
///                                  ▼
///                              ffi2lib channel
///                                  │
///                                  ▼
///                              IOHandle::recv()
///                                  │
///                                  ▼
///                               libdd-rc
/// ```
///
///   1. The FFI host calls into this library with [`rc_conn_recv()`] which
///      copies the payload into an internal queue.
///   2. A consumer in the non-FFI code eventually pulls this incoming message
///      from the queue and processes it.
///
/// # FFI Interface
///
/// This type is represented across the FFI boundary as an [opaque handle]; the
/// host runtime can reference the handle when making subsequent FFI functions,
/// but cannot interact with the internal fields.
///
/// This type is expected to emit [`ConnectionEvent`] lifecycle updates to
/// inform the main (non-FFI) library code of state changes.
///
/// [opaque handle]: https://interrupt.memfault.com/blog/opaque-pointers
#[derive(Debug)]
#[repr(Rust)] // Explicitly not exposing internals across FFI boundary.
pub struct FFIConnection {
    id: ConnectionId,

    /// A handle to the tokio runtime running in the [`Ctx`] this connection is
    /// registered to.
    runtime: tokio::runtime::Handle,

    /// An event sink through which updates for this connection are published.
    events: mpsc::UnboundedSender<ConnectionUpdate<IOHandle>>,

    state: State,
}

#[allow(clippy::boxed_local)] // FFI init/free calls made through box only.
impl FFIConnection {
    pub(super) fn new(
        runtime: tokio::runtime::Handle,
        id: ConnectionId,
        events: mpsc::UnboundedSender<ConnectionUpdate<IOHandle>>,
    ) -> Box<Self> {
        let s = Self {
            runtime,
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
        self.events
            .send(ConnectionUpdate::new(self.id, event))
            .expect("runtime task not running");
    }

    /// Mark the connection as available to handle I/O.
    ///
    /// This call spawns (or reuses a free) OS thread to perform outgoing I/O
    /// calls through the FFI layer, running the [`io_task`].
    ///
    /// # Panics
    ///
    /// This call panics if the connection has not yet been configured with a
    /// [`SendCb`] callback, or is already connected.
    fn set_connected(&mut self) {
        // Correctness: the callback can only be changed when the connection is
        // not in use (and therefore the caller has an exclusive ref).
        //
        // A callback MAY be changed after being set.
        let (send, user_data) = match self.state {
            State::Configured { send, user_data } => (send, user_data),
            State::Init | State::Connected { .. } => {
                panic!("connection not in configured state")
            }
        };

        let (tx, lib2ffi) = mpsc::channel(QUEUE_BUFFER_LEN);
        let (ffi2lib, rx) = mpsc::channel(QUEUE_BUFFER_LEN);
        let io_handle = IOHandle::new(tx, rx);

        let io_task_stop = CancellationToken::new();

        // Spawn an I/O task on its own thread to handle calling across the FFI
        // boundary to push payloads through the send callback.
        //
        // Making these calls off of the runtime thread is important to enable
        // cooperative parallelism and avoid runtime stalls that add latency to
        // all async functions executing at the same time.
        //
        // This I/O task (and the thread it belongs to) is automatically stopped
        // when any of the following occur:
        //
        //  * When set_disconnected() is called, triggering io_task_stop.
        //  * The IOHandle goes out of scope, closing the lib2ffi channel.
        //  * The FFI host returns an error to a send call.
        //  * The runtime is stopped by closing the Ctx (though the connection
        //    SHOULD be disconnected and free'd by the FFI host first).
        //
        // This I/O task captures the send callback and MUST be stopped before
        // the send callback can be freed by the host, meaning the task MUST
        // have stopped prior to set_disconnected() returning complete to a®void
        // this race (and similar):
        //
        //  1. set_connected() spawns I/O task.
        //  2. set_disconnected()
        //  3. FFI host sets the callback to NULL / frees memory it references.
        //  4. I/O task, still running, invokes the send callback.
        //
        // The OS thread executing this I/O task will be reused if another
        // blocking (I/O) task is spawned onto it in the future, else it will
        // eventually be exited by the runtime if unused.
        let io_task = AbortOnDrop::from(self.runtime.spawn_blocking({
            let io_task_stop = io_task_stop.clone();
            move || io_task(lib2ffi, io_task_stop, send, user_data)
        }));

        self.state = State::Connected {
            send,
            user_data,
            io_task,
            io_task_stop,
            ffi2lib,
        };

        self.publish_event(ConnectionEvent::Connected(io_handle));
    }

    /// Receive a payload from the RC backend, to the library.
    ///
    /// # Panics
    ///
    /// This call panics if the connection is not in the "connected" state.
    fn recv_incoming(&self, payload: Result<ServerToClient, DecodingError>) {
        match &self.state {
            State::Connected { ffi2lib, .. } => {
                // Pass the payload to the I/O handle.
                if let Err(_e) = block_on(ffi2lib.send(payload)) {
                    // This can occur if the IOHandle has been dropped before
                    // the connection has closed.
                    error!("IOHandle is not listening for payloads");
                }
            }
            State::Init | State::Configured { .. } => panic!("invalid connection state for recv"),
        }
    }

    /// Mark this connection as being unavailable to deliver I/O.
    ///
    /// Payloads that have been delivered to [`Self::recv_incoming`] but not yet
    /// consumed from the [`IOHandle`] will be available after this call, but
    /// any outgoing payloads via calls to [`IOHandle::send()`] will fail after
    /// this call.
    ///
    /// This call blocks until the [`io_task`] for this connection is stopped.
    ///
    /// # Panics
    ///
    /// This call panics if the connection was not in the "connected" state, or
    /// the [`io_task`] panicked.
    fn set_disconnected(&mut self) {
        let last_state = std::mem::replace(&mut self.state, State::Init);

        match last_state {
            State::Connected {
                send,
                user_data,
                io_task,
                io_task_stop,
                ..
            } => {
                // Trigger the shutdown of the I/O task.
                io_task_stop.cancel();

                // Block this call until the I/O task has stopped, to prevent
                // the race described above.
                block_on(io_task.into_inner()).expect("i/o task shutdown");

                // Restore the configuration state of the FFIConnection,
                // preserving the believed-to-be-valid send callback.
                //
                // Safety: this callback pointer may be dangling, but is not
                // referenced until the FFI host indicates it is safe to do so
                // again.
                self.state = State::Configured { send, user_data };
            }
            State::Init | State::Configured { .. } => {
                panic!("disconnect on connection not in connected state")
            }
        };

        self.publish_event(ConnectionEvent::Disconnected);
    }

    /// Set the [`SendCb`] for this [`FFIConnection`].
    ///
    /// # Panics
    ///
    /// This call panics if the connection is in use ([`State::Connected`]).
    fn set_send_callback(&mut self, cb: SendCb, user_data: SendCbUserData) {
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

        self.state = State::Configured {
            send: cb,
            user_data,
        };
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
}

/// A task run in a dedicated OS thread per [`FFIConnection`] to make outgoing
/// FFI calls via `send`.
fn io_task(
    mut lib2ffi: mpsc::Receiver<ClientToServer>,
    stop: CancellationToken,
    send: SendCb,
    user_data: SendCbUserData,
) {
    debug!("starting connection I/O task");

    loop {
        // Block the thread, waiting for either a payload to dispatch, or a
        // signal to exit.
        let maybe_payload = block_on(async {
            select! {
                _ = stop.cancelled() => {
                    debug!("connection I/O task stopping due to force stop signal");
                    None
                }
                v = lib2ffi.recv() => {v}
            }
        });

        let payload = match maybe_payload {
            Some(v) => v,
            None => {
                break;
            }
        };

        // Serialise the message into a RPC payload, and call into the FFI host
        // to send this data, blocking this thread until send() returns.
        //
        // Safety: this I/O task is spawned only after a FFI host indicates the
        // connection can be used as currently configured via a call to
        // [`rc_conn_connected()`]. This task is killed prior to
        // [`rc_conn_disconnected()`] returning. The FFI host is responsible for
        // and guarantees the callback is valid between these two FFI function
        // calls.
        let buf = Vec::from(&payload);
        let ret = unsafe { send(buf.as_slice().as_ptr(), buf.len() as u32, user_data.0) };

        match ret {
            SendRet::Success => {}

            // The FFI host indicated the connection is closed /
            // erroring.
            //
            // Kill this connection by stopping this I/O task, closing
            // the "outgoing" channel, such that subsequent calls to
            // IOHandle::send() will return a "channel closed" error.
            //
            // Log a message, and include the best effort count of
            // dropped messages (inclusive of the failed message above).
            SendRet::Closed => {
                // Debug log for "normal" runtime behaviour.
                let dropped_messages = lib2ffi.len() + 1;
                debug!(%dropped_messages, "connection indicated as disconnected");
                break;
            }
            SendRet::Unknown => {
                // Warning log for ungraceful I/O error.
                let dropped_messages = lib2ffi.len() + 1;
                warn!(%dropped_messages, "connection I/O error");

                break;
            }
        }
    }

    debug!("stopping connection I/O task"); // Not logged when aborted
}

#[cfg(test)]
mod tests {
    use std::{fmt::Debug, ptr};

    use assert_matches::assert_matches;
    use futures::StreamExt;
    use rc_x509_proto::protocol::v1;
    use tokio::pin;

    use crate::ctx::{rc_free, rc_init};
    use rc_x509_client::{
        ShutdownSignal,
        entrypoint::LibraryEntrypoint,
        host_runtime::{Connection, ConnectionErr},
    };

    use super::*;

    const fn is_send<T: Send>() {}
    const _: () = is_send::<FFIConnection>();

    /// A mock [`LibraryEntrypoint`] that forwards all connection lifecycle
    /// events it observes to the provided event sink.
    #[derive(Debug)]
    struct Entrypoint<IO> {
        events: mpsc::Sender<ConnectionUpdate<IO>>,
    }
    impl<IO> LibraryEntrypoint<IO> for Entrypoint<IO>
    where
        IO: Debug + Send + Sync + 'static,
    {
        async fn entrypoint(
            self,
            _shutdown: ShutdownSignal,
            conn_events: impl futures::Stream<Item = ConnectionUpdate<IO>> + Send + Sync + 'static,
        ) {
            pin!(conn_events);
            while let Some(v) = conn_events.next().await {
                let _ = self.events.send(v).await;
            }
        }
    }

    #[test]
    fn test_connection_init_free() {
        let ctx = unsafe { rc_init() };
        assert!(!ctx.is_null());

        let conn = unsafe { rc_conn_new(ctx) };
        assert!(!conn.is_null());
        assert_matches!(unsafe { &*conn }.state, State::Init);

        unsafe extern "C" fn do_send(
            _data: *const u8,
            _length: u32,
            _user_data: *const c_void,
        ) -> SendRet {
            SendRet::Unknown
        }

        unsafe {
            rc_conn_send_callback(conn, do_send, ptr::null());
            assert_matches!((&*conn).state, State::Configured { .. });
        }

        unsafe { rc_conn_free(conn) };
        unsafe { rc_free(ctx) };
    }

    /// Ensure connections obtained from the FFI layer have monotonic,
    /// sequential connection IDs starting from 0 per [`Ctx`].
    #[test]
    fn test_monotonic_connection_id() {
        let ctx = unsafe { rc_init() };
        assert!(!ctx.is_null());

        // Drive a number of connection creations and assert their IDs start at
        // 0, and increase sequentially.
        for want_id in [0, 1, 2] {
            let conn = unsafe { rc_conn_new(ctx) };
            assert!(!conn.is_null());
            assert_eq!(unsafe { &*conn }.id.as_raw(), want_id);

            unsafe extern "C" fn do_send(
                _data: *const u8,
                _length: u32,
                _user_data: *const c_void,
            ) -> SendRet {
                SendRet::Unknown
            }

            unsafe {
                rc_conn_send_callback(conn, do_send, ptr::null());
                assert_matches!((&*conn).state, State::Configured { .. });
            }

            unsafe { rc_conn_free(conn) };
        }

        unsafe { rc_free(ctx) };
    }

    /// This test drives the lifecycle of a connection, covering:
    ///
    ///   * Expected FFI usage is successful / no panics.
    ///   * Correct connection lifecycle events are emitted by the FFI layer.
    ///   * I/O thread management (creation / shutdown signal).
    ///   * Outgoing I/O is delivered from the IOHandle and into FFI callback.
    ///   * Incoming I/O is delivered from the FFI call, into the IOHandle.
    ///   * Closure of the lifecycle events channel during shutdown (else the
    ///     mock Entrypoint blocks forever and leaks).
    ///   * The SendCb user data from the caller is passed to the callback.
    ///
    #[tokio::test]
    async fn test_connection_lifecycle() {
        // A channel to notify the main thread that the callback succeeded, and
        // provide the payload it saw for verification.
        let (cb_tx, cb_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let cb_tx = Box::new(cb_tx);

        // A send callback that records if it was called at any point.
        unsafe extern "C" fn do_send(
            data: *const u8,
            length: u32,
            user_data: *const c_void,
        ) -> SendRet {
            let got_data = unsafe { slice::from_raw_parts(data, length as _) }.to_vec();
            let got_tx: Box<std::sync::mpsc::Sender<Vec<u8>>> =
                unsafe { Box::from_raw(user_data as _) };

            // Signal the callback was executed.
            got_tx.send(got_data).expect("must be waiting");

            SendRet::Success
        }

        // Configure a Ctx with an entrypoint that forwards all connection
        // events to "conn_events" instead of the real entrypoint called by
        // rc_init().
        let (tx, mut conn_events) = mpsc::channel(100);
        let mut ctx = Ctx::new(Entrypoint { events: tx });

        // FFI call: rc_conn_new()
        let conn = unsafe { rc_conn_new(&raw mut *ctx) };
        assert!(!conn.is_null());
        unsafe {
            let conn = &*conn;
            assert_matches!(conn.state, State::Init);
            assert_eq!(conn.id.as_raw(), 0); // First connection starts at 0.
        }

        // Assert the correct lifecycle event was received.
        let got = conn_events.recv().await.unwrap();
        assert_matches!(got.event(), ConnectionEvent::Init);

        unsafe {
            // Configure the send callback and mark as connected.
            rc_conn_send_callback(conn, do_send, Box::into_raw(cb_tx) as _);
            rc_conn_connected(conn);
        }

        // Assert the connected lifecycle event was received.
        let got = conn_events.recv().await.unwrap();
        let mut io = assert_matches!(got.into_event(), ConnectionEvent::Connected(io) => io);

        //
        // The connection is now active.
        //

        // Drive outgoing data through the I/O task, via the IOHandle.
        io.send(ClientToServer::Pong)
            .await
            .expect("allowed to send");

        // Verify the outgoing payload was delivered through the I/O task, to
        // the callback. This completes asynchronously, so wait on the channel
        // as a signal for it to occur:
        let got = cb_rx.recv().expect("must see callback payload");
        assert_eq!(got, Vec::from(&ClientToServer::Pong));

        // Simulate incoming data.
        let data = rc_x509_proto::encode(&v1::ServerToClient {
            message: Some(v1::server_to_client::Message::Ping(v1::Ping::default())),
        });
        unsafe {
            rc_conn_recv(conn, data.as_slice().as_ptr(), data.len() as u32);
        }
        let got = io
            .take_recv_stream()
            .expect("first call yields stream")
            .next()
            .await
            .expect("data must arrive");
        assert_matches!(got, Ok(ServerToClient::Ping));

        //
        // The connection is now being closed by the FFI host.
        //

        unsafe {
            rc_conn_disconnected(conn);
        }

        // Assert the disconnected lifecycle event was received.
        let got = conn_events.recv().await.unwrap();
        assert_matches!(got.event(), ConnectionEvent::Disconnected);

        // At this point, the IO handle MUST be returning an error to further
        // sends, because the I/O task MUST have stopped.
        //
        // If the I/O task is still running, the Send callback may now be
        // invalid, causing a potential UAF.
        assert_matches!(
            io.send(ClientToServer::Pong).await,
            Err(ConnectionErr::Closed)
        );

        unsafe {
            rc_conn_free(conn);
        }

        // Assert the released lifecycle event was received.
        let got = conn_events.recv().await.unwrap();
        assert_matches!(got.event(), ConnectionEvent::Release);

        // Ctx not freed via FFI because not initialised via FFI.
        ctx.shutdown();
    }
}
