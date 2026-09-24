use tracing::debug;

use crate::connection::handler::SendToServer;
use crate::{codec::ServerToClient, connection::handler::delegate::state::State};

use super::{Fsm, ServerMessageDelegate};

/// The connection has experienced a protocol error and all future messages
/// are ignored - see the module documentation for details.
#[derive(Debug)]
pub(crate) struct Error;

impl Error {
    /// This may not be true, but it is the least wrong - a completed handshake
    /// will not suddenly undo itself. It's also never reported, because no
    /// further protocol violations can occur.
    pub(crate) const IS_HANDSHAKE_COMPLETE: bool = true;
}

impl<IO> ServerMessageDelegate<IO> for Fsm<Error>
where
    IO: SendToServer,
{
    async fn send_hello(self, _reply: &mut IO) -> State {
        unreachable!("send_hello called outside the pre-handshake phase")
    }

    async fn process(self, _msg: ServerToClient, _reply: &mut IO) -> State {
        debug!("dropping message due to protocol error");
        State::Error(self)
    }
}
