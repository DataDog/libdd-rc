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

use rc_crypto::certificate::id::CertId;
use rc_crypto::connection_id::ConnectionId;
use tokio_util::bytes::Bytes;
use tracing::{debug, error};

use crate::{
    codec::{ClientToServer, DetachedSignature, ProtocolError, ServerToClient},
    connection::handler::{
        SendToServer,
        delegate::{retry_send, state::State},
    },
    dispatch::Dispatch,
    host_runtime::CorrelationId,
};

use super::{Fsm, ServerMessageDelegate};

/// The handshake completed successfully.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct Active(pub(super) ConnectionId);

impl Active {
    pub(crate) const IS_HANDSHAKE_COMPLETE: bool = true;
}

impl<IO> ServerMessageDelegate<IO> for Fsm<Active>
where
    IO: SendToServer,
{
    async fn send_hello(self, _reply: &mut IO) -> State {
        unreachable!("send_hello called outside the pre-handshake phase")
    }

    async fn process(self, msg: ServerToClient, reply: &mut IO) -> State {
        match msg {
            ServerToClient::Ping => {
                retry_send(reply, ClientToServer::Pong, &self.stop).await;
                State::Active(self)
            }

            ServerToClient::CertificatePush(..) => unimplemented!(),
            ServerToClient::SetReconnectionData(..) => unimplemented!(),

            ServerToClient::Dispatch {
                correlation_id,
                payload,
                detached_signature,
            } => {
                self.handle_dispatch(reply, correlation_id, payload, detached_signature)
                    .await
            }

            // The client has already completed the handshake, so this ACK is
            // a duplicate.
            ServerToClient::ClientHelloAck { .. } => {
                self.protocol_error(
                    Active::IS_HANDSHAKE_COMPLETE,
                    reply,
                    ProtocolError::HandshakeDuplicateAck,
                )
                .await
            }
        }
    }
}

impl Fsm<Active> {
    /// Process a [`ServerToClient::Dispatch`] request, verifying the
    /// attached [`DetachedSignature`] before forwarding `payload` to the
    /// host application via [`DispatchPublisher`](crate::dispatch::DispatchPublisher).
    async fn handle_dispatch<IO>(
        self,
        reply: &mut IO,
        correlation_id: CorrelationId,
        payload: Bytes,
        detached_signature: Option<DetachedSignature>,
    ) -> State
    where
        IO: SendToServer,
    {
        let connection_id = &self.state.0;

        // Handle the possibility of no signature being sent on the wire - a
        // protocol violation.
        let (signing_cert_id, signature) = match detached_signature {
            Some(DetachedSignature { cert_id, signature }) if !signature.is_empty() => {
                (cert_id, signature)
            }
            _ => {
                error!(%connection_id, %correlation_id, "no signature in dispatch request");
                return self
                    .protocol_error(
                        Active::IS_HANDSHAKE_COMPLETE,
                        reply,
                        ProtocolError::DispatchMissingSignature(correlation_id),
                    )
                    .await;
            }
        };

        // Parse the signing cert ID.
        let signing_cert_id = match CertId::try_from(signing_cert_id.to_vec()) {
            Ok(v) => v,
            Err(e) => {
                error!(error=%e, "received invalid signer cert ID in dispatch request");

                let got_len = e.got_len();
                return self
                    .protocol_error(
                        Active::IS_HANDSHAKE_COMPLETE,
                        reply,
                        ProtocolError::CertIdInvalidLength(got_len),
                    )
                    .await;
            }
        };

        debug!(%connection_id, %correlation_id, %signing_cert_id, ?signature, "received dispatch request");

        // TODO(dom): signature verification

        // TODO(dom): connection ID verification

        // And finally dispatch the request to the host application (via the
        // FFI layer).
        //
        // NOTE: this call to dispatch() internally logs and enqueues a
        // response to the server if this dispatch call fails.
        match self
            .dispatch
            .dispatch(Dispatch {
                correlation_id,
                payload,
            })
            .await
        {
            Ok(()) => debug!(%correlation_id, "payload dispatched"),
            Err(_) => { /* Logged and handled within the dispatch() call */ }
        }

        State::Active(self)
    }
}
