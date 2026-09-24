use crate::{
    codec::{ProtocolError, ServerToClient},
    connection::handler::{
        SendToServer,
        delegate::fsm::{Active, Error, Fsm, Handshaking, PreHandshake, ServerMessageDelegate},
    },
};

/// The current typestate of the [`Fsm`] for the connection.
#[derive(Debug)]
pub(crate) enum State {
    /// No nonce has been generated and no `ClientHello` has been sent.
    PreHandshake(Fsm<PreHandshake>),

    /// The `ClientHello` has been sent and the client is waiting for the
    /// server to return the `ClientHelloAck`.
    Handshaking(Fsm<Handshaking>),

    /// The handshake completed successfully - the connection is accepting
    /// dispatch requests.
    Active(Fsm<Active>),

    /// The connection has experienced a protocol error and all future messages
    /// are ignored.
    ///
    /// When a protocol error occurs, the client sends a
    /// [`ClientToServer::ClientProtocolError`] to the backend reporting the
    /// specifics of the failure for debugging purposes prior to switching to
    /// this phase.
    ///
    /// ## Indirect Connection Close
    ///
    /// A client in this phase is waiting for the connection to close.
    ///
    /// This client cannot directly close the connection held by the FFI
    /// handler, but the server MUST close the connection after receiving a
    /// protocol error, causing the FFI host to close the connection in this
    /// client.
    ///
    /// [`ClientToServer::ClientProtocolError`]:
    ///     rc_x509_proto::protocol::v1::ClientToServer
    Error(Fsm<Error>),
}

impl State {
    /// Send a `ClientHello` handshake message, dispatching to whichever phase
    /// `self` currently is.
    ///
    /// # Panics
    ///
    /// Panics if this is not the first call to `self`.
    pub(crate) async fn send_hello<IO>(self, reply: &mut IO) -> State
    where
        IO: SendToServer,
    {
        match self {
            State::PreHandshake(s) => s.send_hello(reply).await,
            State::Handshaking(s) => s.send_hello(reply).await,
            State::Active(s) => s.send_hello(reply).await,
            State::Error(s) => s.send_hello(reply).await,
        }
    }

    /// Process the decoded `msg`, dispatching to whichever phase `self`
    /// currently is.
    pub(crate) async fn process<IO>(self, msg: ServerToClient, reply: &mut IO) -> State
    where
        IO: SendToServer,
    {
        match self {
            State::PreHandshake(s) => s.process(msg, reply).await,
            State::Handshaking(s) => s.process(msg, reply).await,
            State::Active(s) => s.process(msg, reply).await,
            State::Error(s) => s.process(msg, reply).await,
        }
    }

    /// Log and report a protocol error `reason` to the backend, and
    /// transition to the terminal [`Error`] phase, dispatching to whichever
    /// phase `self` currently is.
    pub(crate) async fn protocol_error<IO>(self, reply: &mut IO, reason: ProtocolError) -> State
    where
        IO: SendToServer,
    {
        match self {
            State::PreHandshake(s) => {
                s.protocol_error(PreHandshake::IS_HANDSHAKE_COMPLETE, reply, reason)
                    .await
            }
            State::Handshaking(s) => {
                s.protocol_error(Handshaking::IS_HANDSHAKE_COMPLETE, reply, reason)
                    .await
            }
            State::Active(s) => {
                s.protocol_error(Active::IS_HANDSHAKE_COMPLETE, reply, reason)
                    .await
            }
            State::Error(s) => {
                s.protocol_error(Error::IS_HANDSHAKE_COMPLETE, reply, reason)
                    .await
            }
        }
    }
}
