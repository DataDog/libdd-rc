use crate::connection::IOHandle;

/// A [`ConnectionId`] uniquely identifies a single connection managed by the
/// FFI host.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub(crate) struct ConnectionId(usize);

/// Lifecycle events for a single I/O connection brokered by the FFI host.
///
/// The lifecycle event is associated with a [`ConnectionId`] identifying the
/// underlying connection
///
/// Valid state transitions for a connection are:
///
/// ```text
///                         ┌──────────────┐
///                     ┌───│     Init     │
///                     │   └──────────────┘
///                     │           │
///                     │           ▼
///                     │   ┌──────────────┐
///                     │   │  Connected   │◀──┐
///                     │   └──────────────┘   │
///                     │           │          │   Reconnect &
///                     │           ▼          │      reuse
///                     │   ┌──────────────┐   │
///                     │   │ Disconnected │───┘
///                     │   └──────────────┘
///                     │           │
///                     │           ▼
///                     │   ┌──────────────┐
///                     └──▶│   Release    │
///                         └──────────────┘
/// ```
///
/// The FFI host emits lifecycle events into this client library, and as such
/// the correctness of lifecycle transitions depends on the correctness of the
/// FFI host application.
///
/// Implementations MUST not panic if an invalid state transition is reported,
/// instead it SHOULD refuse to change state and raise an error.
///
/// Note that:
///
///   * A connection does not need to ever transition through the
///     [`Self::Connected`] state; it can start in the [`Self::Init`] state and
///     transition to the [`Self::Release`] state immediately after.
///
///   * A connection can be reused after becoming disconnected by transitioning
///     back to the [`Self::Connected`] state.
///
#[derive(Debug)]
pub(crate) enum ConnectionEvent {
    /// A new connection has been created by the FFI host.
    Init,

    /// The FFI host has established a connection to the RC backend for a
    /// [`ConnectionId`] that has previously received an
    /// [`ConnectionEvent::Init`].
    Connected(IOHandle),

    /// The FFI host has lost (or closed) the connection to the RC backend.
    Disconnected,

    /// The FFI host will not reuse this connection - all resources held by it
    /// should be freed.
    Release,
}

/// A [`ConnectionUpdate`] contains a [`ConnectionEvent`] update, and the
/// corresponding [`ConnectionId`] it applies to.
#[derive(Debug)]
pub(crate) struct ConnectionUpdate {
    id: ConnectionId,
    event: ConnectionEvent,
}

impl ConnectionUpdate {
    /// Get the [`ConnectionId`] this [`ConnectionEvent`] this update applies
    /// to.
    pub(crate) fn id(&self) -> ConnectionId {
        self.id
    }

    /// Peek at the underlying [`ConnectionEvent`] in this update.
    pub(crate) fn event(&self) -> &ConnectionEvent {
        &self.event
    }

    /// Extract the owned [`ConnectionEvent`].
    pub(crate) fn into_event(self) -> ConnectionEvent {
        self.event
    }
}
