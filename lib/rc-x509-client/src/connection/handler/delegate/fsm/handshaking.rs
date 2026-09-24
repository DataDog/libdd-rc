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

use rc_crypto::connection_id::IdNonce;
use tracing::{debug, error};

use crate::{
    codec::{ClientToServer, ProtocolError, ServerToClient},
    connection::handler::{
        SendToServer,
        delegate::{retry_send, state::State},
    },
};

use super::{Active, Fsm, ServerMessageDelegate};

/// This client has sent the [`ClientToServer::ClientHello`] and is waiting for
/// the server to return the [`ServerToClient::ClientHelloAck`].
#[derive(Debug)]
pub(crate) struct Handshaking(pub(super) IdNonce);

impl Handshaking {
    pub(crate) const IS_HANDSHAKE_COMPLETE: bool = false;
}

impl<IO> ServerMessageDelegate<IO> for Fsm<Handshaking>
where
    IO: SendToServer,
{
    async fn send_hello(self, _reply: &mut IO) -> State {
        unreachable!("send_hello called outside the pre-handshake phase")
    }

    async fn process(mut self, msg: ServerToClient, reply: &mut IO) -> State {
        match msg {
            ServerToClient::Ping => {
                retry_send(reply, ClientToServer::Pong, &self.stop).await;
                State::Handshaking(self)
            }

            ServerToClient::CertificatePush(..) => unimplemented!(),
            ServerToClient::SetReconnectionData(..) => unimplemented!(),

            ServerToClient::ClientHelloAck {
                connection_id: proposed_id,
            } => {
                debug!(?proposed_id, "obtained unverified connection ID");

                // Take the nonce, leaving a placeholder behind - it is
                // discarded either way, since `self` transitions to a
                // different phase (`Active` or `Error`) below.
                let id_nonce = std::mem::take(&mut self.state.0);

                // Verify the connection ID was derived from the client nonce.
                let connection_id = match proposed_id.verify(id_nonce) {
                    Ok(v) => v,
                    Err(e) => {
                        error!(error=%e, "connection ID verification failure");

                        return self
                            .protocol_error(
                                Handshaking::IS_HANDSHAKE_COMPLETE,
                                reply,
                                ProtocolError::HandshakeConnectionIdRejected,
                            )
                            .await;
                    }
                };

                debug!(%connection_id, "connection handshake complete");

                State::Active(self.into_state(Active(connection_id)))
            }

            // The connection ID must have been established before a dispatch
            // request can arrive.
            ServerToClient::Dispatch { correlation_id, .. } => {
                self.protocol_error(
                    Handshaking::IS_HANDSHAKE_COMPLETE,
                    reply,
                    ProtocolError::DispatchBeforeHandshake(correlation_id),
                )
                .await
            }
        }
    }
}
