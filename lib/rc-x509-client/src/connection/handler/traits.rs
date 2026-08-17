use std::fmt::Debug;

use crate::{
    codec::{ClientToServer, ServerToClient},
    host_runtime::{Connection, ConnectionErr},
};

/// A [`ServerToClient`] message processor.
///
/// The implementation can dispatch any number of responses to the server via
/// the `reply` handle.
pub(super) trait ServerMessageDelegate<IO: SendToServer>: Debug + Send + Sync {
    /// Process the request in `msg`.
    fn process(
        &mut self,
        msg: ServerToClient,
        reply: &mut IO,
    ) -> impl Future<Output = ()> + Send + Sync;
}

/// A subtype of a [`Connection`] implementation, capable of sending responses
/// to the server only.
///
/// This trait is automatically implemented for all [`Connection`]
/// implementations.
pub(super) trait SendToServer: Debug + Send + Sync {
    /// Attempt to push `reply` to the server.
    fn send(
        &mut self,
        reply: ClientToServer,
    ) -> impl Future<Output = Result<(), ConnectionErr>> + Send + Sync;
}

impl<T> SendToServer for T
where
    T: Connection,
{
    async fn send(&mut self, reply: ClientToServer) -> Result<(), ConnectionErr> {
        T::send(self, reply).await
    }
}
