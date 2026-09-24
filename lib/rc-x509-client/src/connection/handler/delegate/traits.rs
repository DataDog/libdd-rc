use std::fmt::Debug;

use crate::{
    codec::ServerToClient,
    connection::handler::{SendToServer, delegate::state::State},
};

/// A state machine that processes [`ServerToClient`] messages.
///
/// Each implementation consumes `self` and returns the (possibly different)
/// next [`State`].
pub(crate) trait ServerMessageDelegate<IO>: Debug + Send + Sync + Sized
where
    IO: SendToServer,
{
    /// Send a `ClientHello` handshake message.
    ///
    /// # Panics
    ///
    /// Panics if this is not the first call to `self` (the state machine).
    fn send_hello(self, reply: &mut IO) -> impl Future<Output = State> + Send + Sync;

    /// Process the decoded `msg`.
    fn process(
        self,
        msg: ServerToClient,
        reply: &mut IO,
    ) -> impl Future<Output = State> + Send + Sync;
}
