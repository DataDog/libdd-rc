//! Initial FSM state.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::{
    codec::{ClientToServer, ProtocolError, ServerToClient},
    connection::handler::{
        SendToServer,
        delegate::{retry_send, state::State},
        hello::build_hello,
    },
    dispatch::DispatchPublisher,
    metrics::InstanceMetrics,
};

use super::{Fsm, Handshaking, ServerMessageDelegate};

/// The opening handshake has not been started (no nonce has been generated and
/// no [`ClientToServer::ClientHello`] sent).
///
/// Call [`ServerMessageDelegate::send_hello()`] to begin the handshake.
#[derive(Debug)]
pub(crate) struct PreHandshake {
    app_name: String,
    app_version: String,
}

impl Fsm<PreHandshake> {
    pub(crate) fn new(
        metrics: Arc<InstanceMetrics>,
        stop: CancellationToken,
        dispatch: DispatchPublisher,
        app_name: String,
        app_version: String,
    ) -> Self {
        Self {
            metrics,
            stop,
            dispatch,
            state: PreHandshake {
                app_name,
                app_version,
            },
        }
    }
}

impl PreHandshake {
    pub(crate) const IS_HANDSHAKE_COMPLETE: bool = false;
}

impl<IO> ServerMessageDelegate<IO> for Fsm<PreHandshake>
where
    IO: SendToServer,
{
    /// Send a `ClientHello`, (re)starting the handshake and transitioning to
    /// [`Handshaking`] with a freshly generated nonce.
    async fn send_hello(self, reply: &mut IO) -> State {
        let (nonce, hello) =
            build_hello(&self.state.app_name, &self.state.app_version, &self.metrics);
        retry_send(reply, hello, &self.stop).await;

        State::Handshaking(self.into_state(Handshaking(nonce)))
    }

    async fn process(self, msg: ServerToClient, reply: &mut IO) -> State {
        match msg {
            ServerToClient::Ping => {
                retry_send(reply, ClientToServer::Pong, &self.stop).await;
                State::PreHandshake(self)
            }

            ServerToClient::CertificatePush(..) => unimplemented!(),
            ServerToClient::SetReconnectionData(..) => unimplemented!(),

            // The client has not yet sent the HELLO, so an ACK is a protocol
            // violation.
            ServerToClient::ClientHelloAck { .. } => {
                self.protocol_error(
                    PreHandshake::IS_HANDSHAKE_COMPLETE,
                    reply,
                    ProtocolError::HandshakeAckBeforeHello,
                )
                .await
            }

            // The connection ID must have been established before a dispatch
            // request can arrive.
            ServerToClient::Dispatch { correlation_id, .. } => {
                self.protocol_error(
                    PreHandshake::IS_HANDSHAKE_COMPLETE,
                    reply,
                    ProtocolError::DispatchBeforeHandshake(correlation_id),
                )
                .await
            }
        }
    }
}
