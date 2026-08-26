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

//! This module is responsible for processing [`ServerToClient`] messages from
//! the backend.

use std::{fmt::Debug, sync::Arc, time::Duration};

use rc_crypto::{
    certificate::id::CertId,
    connection_id::{ConnectionId, IdNonce, UntrustedConnectionId},
};
use tokio_util::{bytes::Bytes, sync::CancellationToken};
use tracing::{debug, error, warn};

use crate::{
    codec::{ClientToServer, DecodingError, DetachedSignature, ProtocolError, ServerToClient},
    connection::handler::{SendToServer, ServerMessageDelegate, hello::build_hello},
    dispatch::{Dispatch, DispatchPublisher},
    host_runtime::{ConnectionErr, CorrelationId},
    metrics::InstanceMetrics,
};

/// The current state of the connection.
#[derive(Debug)]
enum ConnState {
    /// The opening handshake has not been started (no [`IdNonce`] has been
    /// generated and no [`ClientToServer::ClientHello`] sent).
    PreHandshake,

    /// This client has sent the [`ClientToServer::ClientHello`] and is waiting
    /// for the server to return the [`ServerToClient::ClientHelloAck`].
    Handshaking(IdNonce),

    /// The handshake completed successfully.
    #[allow(dead_code)]
    Active(ConnectionId),

    /// The connection has experienced a protocol error and all future messages
    /// are ignored.
    ///
    /// When a protocol error occurs, the client sends a
    /// [`ClientToServer::ClientProtocolError`] to the backend reporting the
    /// specifics of the failure for debugging purposes prior to switching to
    /// this state.
    ///
    /// ## Indirect Connection Close
    ///
    /// A client in this state is waiting for the connection to close.
    ///
    /// This client cannot directly close the connection held by the FFI
    /// handler, but the server MUST close the connection after receiving a
    /// protocol error, causing the FFI host to close the connection in this
    /// client.
    Error,
}

impl ConnState {
    /// Returns true if the client believes the handshake is complete.
    fn is_handshake_complete(&self) -> bool {
        match self {
            ConnState::PreHandshake | ConnState::Handshaking(..) => false,
            ConnState::Active(..) | ConnState::Error => true,
        }
    }
}

/// Handler for [`ServerToClient`] messages (an implementation of
/// [`ServerMessageDelegate`]).
#[derive(Debug)]
pub(crate) struct MessageDelegate {
    metrics: Arc<InstanceMetrics>,
    stop: CancellationToken,
    #[allow(dead_code)]
    dispatch: DispatchPublisher,

    state: ConnState,
}

impl MessageDelegate {
    pub(crate) fn new(
        stop: CancellationToken,
        metrics: Arc<InstanceMetrics>,
        dispatch: DispatchPublisher,
    ) -> Self {
        Self {
            metrics,
            stop,
            dispatch,
            state: ConnState::PreHandshake,
        }
    }

    /// Log and report a protocol error `reason` to the backend, and set the
    /// connection into the error state.
    async fn protocol_error<IO>(&mut self, io: &mut IO, reason: ProtocolError)
    where
        IO: SendToServer,
    {
        warn!(error = ?reason, "protocol error");

        // Record the current state, before changing it.
        let is_handshake_complete = self.state.is_handshake_complete();

        // Mark the connection as having failed.
        self.state = ConnState::Error;

        // Notify the server of the protocol error:
        retry_send(
            io,
            ClientToServer::ProtocolError {
                reason,
                is_handshake_complete,
            },
            &self.stop,
        )
        .await;
    }

    /// Process a [`ServerToClient::ClientHelloAck`] from the backend, that
    /// proposes using `proposed_id` as the [`ConnectionId`].
    ///
    /// The client verifies the proposal includes the client-provided nonce, and
    /// transitions the connection state to the appropriate outcome. Any error
    /// is reported to the backend automatically.
    async fn handle_hello_ack<IO>(&mut self, io: &mut IO, proposed_id: UntrustedConnectionId)
    where
        IO: SendToServer,
    {
        debug!(?proposed_id, "obtained unverified connection ID");

        // Process the handshake ACK from the server, which is dependent on the
        // client connection state:
        let id_nonce = match &mut self.state {
            // This is the only acceptable state for an ACK to be received:
            ConnState::Handshaking(id_nonce) => std::mem::take(id_nonce),

            // In the pre-handshake state, the client has not yet sent the
            // HELLO, so this is a protocol violation:
            ConnState::PreHandshake => {
                return self
                    .protocol_error(io, ProtocolError::HandshakeAckBeforeHello)
                    .await;
            }

            // The client has already completed the handshake, meaning this ACK
            // is a duplicate:
            ConnState::Active(..) => {
                return self
                    .protocol_error(io, ProtocolError::HandshakeDuplicateAck)
                    .await;
            }

            // This should not be reachable (it is checked by the caller prior
            // to this fn call) - the correct response is to ignore the message
            // in either case:
            ConnState::Error => return, // Checked before calling this fn.
        };

        // Verify the connection ID was derived from the client nonce.
        let connection_id = match proposed_id.verify(id_nonce) {
            Ok(v) => v,
            Err(e) => {
                error!(error=%e, "connection ID verification failure");

                return self
                    .protocol_error(io, ProtocolError::HandshakeConnectionIdRejected)
                    .await;
            }
        };

        debug!(%connection_id, "connection handshake complete");

        // Success - the state now changes to reflect the finalised handshake.
        self.state = ConnState::Active(connection_id)
    }

    /// Process a [`ServerToClient::Dispatch`] request, verifying the attached
    /// [`DetachedSignature`] before forwarding `payload` to the host
    /// application via [`DispatchPublisher`].
    #[allow(dead_code)]
    async fn handle_dispatch<IO>(
        &mut self,
        io: &mut IO,
        correlation_id: CorrelationId,
        payload: Bytes,
        detached_signature: Option<DetachedSignature>,
    ) where
        IO: SendToServer,
    {
        // First check the state and read the connection ID for later
        // verification.
        let connection_id = match &self.state {
            ConnState::Active(connection_id) => connection_id,

            // No other state is acceptable.
            //
            // The connection ID must have been established before a dispatch
            // request can arrive.
            ConnState::PreHandshake | ConnState::Handshaking(..) => {
                return self
                    .protocol_error(io, ProtocolError::DispatchBeforeHandshake(correlation_id))
                    .await;
            }

            // This should not be reachable (it is checked by the caller prior
            // to this fn call) - the correct response is to ignore the message
            // in either case:
            ConnState::Error => return,
        };

        // Handle the possibility of no signature being sent on the wire - a
        // protocol violation.
        let (signing_cert_id, signature) = match detached_signature {
            Some(DetachedSignature { cert_id, signature }) if !signature.is_empty() => {
                (cert_id, signature)
            }
            _ => {
                error!(%connection_id, %correlation_id, "no signature in dispatch request");
                return self
                    .protocol_error(io, ProtocolError::DispatchMissingSignature(correlation_id))
                    .await;
            }
        };

        // Parse the signing cert ID.
        let signing_cert_id = match CertId::try_from(signing_cert_id.as_ref()) {
            Ok(v) => v,
            Err(e) => {
                error!(error=%e, "received invalid signer cert ID in dispatch request");

                self.protocol_error(io, ProtocolError::CertIdInvalidLength(e.got_len()))
                    .await;
                return;
            }
        };

        debug!(%connection_id, %correlation_id, %signing_cert_id, ?signature, "received dispatch request");

        // TODO(dom): signature verification

        // TODO(dom): connection ID verification

        // And finally dispatch the request to the host application (via the FFI
        // layer).
        //
        // NOTE: this call to dispatch() internally logs and enqueues a response
        // to the server if this dispatch call fails.
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
    }
}

impl<IO> ServerMessageDelegate<IO> for MessageDelegate
where
    IO: SendToServer,
{
    async fn process(&mut self, msg: Result<ServerToClient, DecodingError>, io: &mut IO) {
        // If the connection has been marked as having experienced a protocol
        // error, all further messages are dropped. This client is waiting for
        // the server to close the connection.
        if matches!(self.state, ConnState::Error) {
            debug!("dropping message due to protocol error");
            return;
        }

        // Report any deserialisation errors to the server.
        let msg = match msg {
            Ok(v) => v,
            Err(e) => {
                warn!(error=%e, "dropping invalid message from server");
                return self
                    .protocol_error(io, ProtocolError::DeserialisationFailed(e.to_string()))
                    .await;
            }
        };

        // TODO(dom): remove filter_implemented().

        match msg {
            ServerToClient::Ping => retry_send(io, ClientToServer::Pong, &self.stop).await,

            ServerToClient::CertificatePush(..) => unimplemented!(),
            ServerToClient::SetReconnectionData(..) => unimplemented!(),

            // A Dispatch can only occur after the handshake is complete.
            ServerToClient::Dispatch {
                correlation_id,
                payload,
                detached_signature,
            } => {
                self.handle_dispatch(io, correlation_id, payload, detached_signature)
                    .await
            }

            // A client ACK must be received exactly once, when the connection
            // is in the "Handshaking" state.
            ServerToClient::ClientHelloAck { connection_id } => {
                self.handle_hello_ack(io, connection_id).await
            }
        }
    }

    async fn send_hello(&mut self, reply: &mut IO) {
        if matches!(self.state, ConnState::Error) {
            debug!("refusing to send hello after protocol error");
            return;
        }

        let (nonce, hello) = build_hello("test", &self.metrics);
        retry_send(reply, hello, &self.stop).await;

        // Retain the nonce for verification later.
        self.state = ConnState::Handshaking(nonce);
    }
}

/// Retry sending `value` over `io` until it succeeds, or `stop` is cancelled.
///
/// This function does not return an indication of success, as it should only be
/// cancelled if the connection is closing.
pub(super) async fn retry_send<IO>(io: &mut IO, value: ClientToServer, stop: &CancellationToken)
where
    IO: SendToServer,
{
    loop {
        match io.send(value.clone()).await {
            Ok(_) => {
                debug!("message sent");
                break;
            }
            Err(ConnectionErr::Closed) => {
                debug!("connection closed - aborting message send");
                return;
            }
            Err(e @ (ConnectionErr::Unknown | ConnectionErr::QueueFull)) => {
                warn!(error=%e, "failed to send message to server")
            }
        }

        tokio::select! {
            biased;

            _ = stop.cancelled() => {
                debug!("send aborted - connection closing");
                return;
            }

            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use futures::FutureExt;
    use proptest::{option, prelude::*, strategy::LazyJust};
    use rc_x509_trust::cert::UntrustedCertBytes;
    use tokio_util::bytes::Bytes;

    use crate::{
        build_version::BuildVersion,
        codec::{DetachedSignature, tests::SAMPLE_CERT_DER},
        connection::ReconnectionData,
        dispatch::new_dispatcher_interconnect,
        host_runtime::CorrelationId,
        mocks::io::new_io_pair,
        tests::arbitrary_bytes,
    };

    use super::*;

    /// Drive `d` through a complete, successful handshake: read the
    /// [`ClientToServer::ClientHello`] sent by `d`, derive the resulting
    /// [`ConnectionId`] from the client-provided nonce, and deliver the
    /// [`ServerToClient::ClientHelloAck`] response back to `d`.
    async fn do_handshake(
        d: &mut MessageDelegate,
        client: &mut crate::mocks::io::MockIO,
        server: &mut crate::mocks::io::MockIOServer,
    ) {
        d.send_hello(client).await;

        let client_nonce = assert_matches!(
            server.recv().await,
            Some(ClientToServer::ClientHello { client_nonce, .. }) => client_nonce
        );

        let server_nonce = IdNonce::default();
        let connection_id = ConnectionId::new(&client_nonce, server_nonce.as_bytes());

        d.process(
            Ok(ServerToClient::ClientHelloAck {
                connection_id: UntrustedConnectionId::new(
                    Bytes::copy_from_slice(server_nonce.as_bytes()),
                    Bytes::copy_from_slice(connection_id.as_bytes()),
                ),
            }),
            client,
        )
        .await;
    }

    /// A successful send does not retry.
    #[tokio::test]
    async fn test_retry_send_success() {
        let (mut client, mut server) = new_io_pair();
        let stop = CancellationToken::default();

        retry_send(&mut client, ClientToServer::Pong, &stop).await;

        assert_eq!(server.recv().await, Some(ClientToServer::Pong));
    }

    /// A [`ConnectionErr::Closed`] error aborts the send immediately, without
    /// retrying.
    #[tokio::test]
    async fn test_retry_send_aborts_on_closed_connection() {
        let (mut client, server) = new_io_pair();
        let stop = CancellationToken::default();

        // Close the transport by dropping the server-side handle.
        drop(server);

        // Does not hang despite the stop token never being cancelled - the
        // closed connection is terminal.
        tokio::time::timeout(
            Duration::from_secs(5),
            retry_send(&mut client, ClientToServer::Pong, &stop),
        )
        .await
        .expect("timeout");
    }

    /// A send that keeps failing is retried, backing off between attempts,
    /// until the stop signal is observed.
    #[tokio::test(start_paused = true)]
    async fn test_retry_send_retries_until_stopped() {
        let (mut client, _server) = new_io_pair();
        let stop = CancellationToken::default();

        // Fill the bounded channel so that all sends fail with
        // ConnectionErr::QueueFull, forcing retries.
        while SendToServer::send(&mut client, ClientToServer::Pong)
            .await
            .is_ok()
        {}

        let task_stop = stop.clone();
        let task = tokio::spawn(async move {
            retry_send(&mut client, ClientToServer::Pong, &task_stop).await;
        });

        // Allow a handful of retry attempts to elapse - the queue remains
        // full throughout, so none of them should succeed and the task
        // should not have completed.
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert!(!task.is_finished());

        // Request a shutdown - the in-flight retry loop should observe it
        // and return, even though the send is still failing.
        stop.cancel();

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("timeout")
            .expect("retry_send task panicked");
    }

    /// Test handling of a PING server message.
    #[tokio::test]
    async fn test_ping_pong() {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let mut d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
        );

        let (mut client, mut server) = new_io_pair();

        d.process(Ok(ServerToClient::Ping), &mut client).await;

        let got = server.recv().await.expect("must reply");
        assert_matches!(got, ClientToServer::Pong);
    }

    /// A message that could not be decoded off the wire raises a protocol
    /// error, and transitions the connection into the error state.
    #[tokio::test]
    async fn test_decode_error() {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let mut d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
        );

        let (mut client, mut server) = new_io_pair();

        d.process(Err(DecodingError::NoMessage), &mut client).await;

        assert_matches!(
            server.recv().await,
            Some(ClientToServer::ProtocolError {
                reason,
                is_handshake_complete
            }) => {
                assert!(!is_handshake_complete);
                assert_matches!(reason, ProtocolError::DeserialisationFailed(msg) => {
                    // Error message is reported to the server:
                    assert_eq!(msg, DecodingError::NoMessage.to_string());
                });
            }
        );

        assert_matches!(d.state, ConnState::Error);
    }

    /// Happy path test for a successful handshake.
    #[tokio::test]
    async fn test_handshake() {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let mut d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
        );

        // The initial state is "pre-handshake":
        assert_matches!(d.state, ConnState::PreHandshake);

        let (mut client, mut server) = new_io_pair();

        // Trigger the delegate to send the initial handshake message.
        d.send_hello(&mut client).await;

        // Which drives the state to "handshaking":
        assert_matches!(d.state, ConnState::Handshaking(..));

        // Verify the data provided in the handshake, and extract the nonce:
        let client_nonce = assert_matches!(
            server.recv().await,
            Some(ClientToServer::ClientHello {
                client_nonce,
                graceful,
                ungraceful,
                last_closed_connection_duration,
                reconnection_data,
                version_info,
                app_name
            }) => {
                assert_eq!(graceful.as_raw(), 0);
                assert_eq!(ungraceful.as_raw(), 0);
                assert_eq!(last_closed_connection_duration.as_seconds(), 0);
                assert_eq!(reconnection_data, None);
                assert_eq!(version_info, BuildVersion::from_build());
                assert_eq!(app_name, "test");
                assert_eq!(client_nonce.len(), 16); // 128 bits of randomness.

                client_nonce
            }
        );

        // Derive the final connection ID:
        let server_nonce = IdNonce::default();
        let connection_id = ConnectionId::new(&client_nonce, server_nonce.as_bytes());

        // Deliver the ACK to the delegate:
        d.process(
            Ok(ServerToClient::ClientHelloAck {
                connection_id: UntrustedConnectionId::new(
                    Bytes::copy_from_slice(server_nonce.as_bytes()),
                    Bytes::copy_from_slice(connection_id.as_bytes()),
                ),
            }),
            &mut client,
        )
        .await;

        // Which completes the handshake for the client:
        assert_matches!(d.state, ConnState::Active(..));
    }

    /// Generate an arbitrary ServerToClient message.
    fn any_server_to_client() -> impl Strategy<Value = ServerToClient> {
        prop_oneof![
            arbitrary_valid_dispatch_request(),
            LazyJust::new(|| ServerToClient::Ping),
            LazyJust::new(|| ServerToClient::CertificatePush(UntrustedCertBytes::new(
                SAMPLE_CERT_DER
            ))),
            LazyJust::new(|| ServerToClient::ClientHelloAck {
                connection_id: UntrustedConnectionId::new(
                    Bytes::from_static(&[1, 2, 3, 4]),
                    Bytes::from_static(&[5, 6, 7, 8])
                ),
            }),
            arbitrary_bytes(0..1028)
                .prop_map(|v| ServerToClient::SetReconnectionData(ReconnectionData::new(v))),
        ]
    }

    /// Generate a random, but valid, dispatch request.
    fn arbitrary_valid_dispatch_request() -> impl Strategy<Value = ServerToClient> {
        (
            any::<u64>(),                                             // ID
            arbitrary_bytes(0..1028),                                 // payload
            arbitrary_bytes(CertId::MIN_LENGTH..=CertId::MAX_LENGTH), // cert ID
            arbitrary_bytes(1..1028),                                 // signature (non-empty)
        )
            .prop_map(
                |(id, payload, cert_id, signature)| ServerToClient::Dispatch {
                    correlation_id: CorrelationId::new(id),
                    payload,
                    detached_signature: Some(DetachedSignature { cert_id, signature }),
                },
            )
    }

    /// Generate an arbitrary [`ServerToClient::Dispatch`] that is logically
    /// malformed in such a way that it causes the client to raise a protocol
    /// error.
    fn arbitrary_invalid_dispatch_request() -> impl Strategy<Value = ServerToClient> {
        prop_oneof![
            // No signature:
            arbitrary_valid_dispatch_request().prop_map(|mut v| {
                match &mut v {
                    ServerToClient::Dispatch {
                        detached_signature, ..
                    } => *detached_signature = None,
                    _ => unreachable!(),
                };

                v
            }),
            // Cert ID too small / empty:
            (
                arbitrary_valid_dispatch_request(),
                arbitrary_bytes(0..CertId::MIN_LENGTH)
            )
                .prop_map(|(mut v, id)| {
                    match &mut v {
                        ServerToClient::Dispatch {
                            detached_signature: Some(DetachedSignature { cert_id, .. }),
                            ..
                        } => *cert_id = id,
                        _ => unreachable!(),
                    };

                    v
                }),
            // Cert ID too big:
            (
                arbitrary_valid_dispatch_request(),
                arbitrary_bytes((CertId::MAX_LENGTH + 1)..1028)
            )
                .prop_map(|(mut v, id)| {
                    match &mut v {
                        ServerToClient::Dispatch {
                            detached_signature: Some(DetachedSignature { cert_id, .. }),
                            ..
                        } => *cert_id = id,
                        _ => unreachable!(),
                    };

                    v
                }),
            // Signature empty
            arbitrary_valid_dispatch_request().prop_map(|mut v| {
                match &mut v {
                    ServerToClient::Dispatch {
                        detached_signature: Some(DetachedSignature { signature, .. }),
                        ..
                    } => *signature = Bytes::default(),
                    _ => unreachable!(),
                };

                v
            }),
        ]
    }

    /// Returns true if the message yielded by `input` is a message type that
    /// should be accepted by the client at any time.
    fn filter_allowed_at_any_time(
        input: impl Strategy<Value = ServerToClient>,
    ) -> impl Strategy<Value = ServerToClient> {
        filter_implemented(input).prop_filter("allowed at any time filter", |v| match v {
            // These message types have ordering restrictions:
            ServerToClient::Dispatch { .. } | ServerToClient::ClientHelloAck { .. } => false,
            _ => true,
        })
    }

    /// Returns true if the message yielded by `input` is a message type that
    /// should be accepted by the client after the handshake.
    fn filter_allowed_after_handshake(
        input: impl Strategy<Value = ServerToClient>,
    ) -> impl Strategy<Value = ServerToClient> {
        input.prop_filter("allowed after handshake filter", |v| {
            !matches!(v, ServerToClient::ClientHelloAck { .. })
        })
    }

    // A temporary filter until all handlers are implemented.
    fn filter_implemented(
        input: impl Strategy<Value = ServerToClient>,
    ) -> impl Strategy<Value = ServerToClient> {
        input.prop_filter("implemented filter", |v| {
            !matches!(
                v,
                ServerToClient::CertificatePush(..) | ServerToClient::SetReconnectionData(..)
            )
        })
    }

    /// Returns true if a server sending `v` should expect a reply.
    fn has_reply(v: &ServerToClient) -> bool {
        match v {
            ServerToClient::Ping | ServerToClient::Dispatch { .. } => true,
            ServerToClient::CertificatePush(..)
            | ServerToClient::ClientHelloAck { .. }
            | ServerToClient::SetReconnectionData(..) => false,
        }
    }

    proptest! {
        /// Assert that the message types accepted by the
        /// `filter_allowed_at_any_time` function can be delivered at any stage
        /// of the handshake while still leading to a successful handshake.
        ///
        /// This optimisation allows PING/PONG messages to be sent, and
        /// certificates pre-staged on the client in parallel to the client
        /// generating and sending the HELLO message to reduce end-to-end
        /// latency for the first dispatch after connecting.
        #[test]
        fn prop_message_types_allowed_during_handshake(
            pre_handshake in option::of(filter_allowed_at_any_time(any_server_to_client())),
            during_handshake in option::of(filter_allowed_at_any_time(any_server_to_client())),
            post_handshake in option::of(filter_allowed_at_any_time(any_server_to_client())),
        ) {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(prop_message_types_allowed_during_handshake_body(pre_handshake, during_handshake, post_handshake));
        }

        /// Any non-handshake message can be delivered after the handshake has
        /// completed without causing it to transition into the error state.
        #[test]
        fn prop_any_message_after_handshake(
            msg in filter_allowed_after_handshake(filter_implemented(any_server_to_client())),
        ) {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(prop_any_message_after_handshake_body(msg));
        }

        /// Deliver a ClientHelloAck before the client sends the ClientHello,
        /// and ensure a protocol error is reported.
        ///
        /// Assert all subsequent messages from the server are ignored.
        #[test]
        fn prop_handshake_ack_before_hello(
            does_send_hello_after_ack in any::<bool>(),
            post_ack_msg in any_server_to_client(),
        ) {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(prop_handshake_ack_before_hello_body(does_send_hello_after_ack, post_ack_msg));
        }

        /// Deliver two ClientHelloAck and ensure a protocol error is reported.
        ///
        /// Assert all subsequent messages from the server are ignored.
        #[test]
        fn prop_handshake_duplicate_ack(
            post_ack_msg in any_server_to_client(),
        ) {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(prop_handshake_duplicate_body(post_ack_msg));
        }

        /// Assert the client rejects connection IDs that cannot be proven to
        /// have been derived from the client nonce.
        #[test]
        fn prop_handshake_connection_id_rejected(
            server_nonce in any::<[u8; 16]>(),
            proposed_id in any::<[u8; 16]>(),
            post_error_msg in any_server_to_client(),
        ) {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(prop_handshake_connection_id_rejected_body(server_nonce, proposed_id, post_error_msg));
        }

        /// Assert that a message that causes a deserialisation error causes the
        /// client to report a protocol error and refuse subsequent messages.
        #[test]
        fn prop_deserialisation_error_rejects_messages(
            msg in filter_allowed_after_handshake(filter_implemented(any_server_to_client())),
        ) {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(prop_deserialisation_error_rejects_messages_body(msg));
        }

        /// An invalid dispatch request causes the client to transition to the
        /// error state, raise a protocol error, and refuse subsequent requests
        /// of any sort.
        #[test]
        fn prop_invalid_dispatch_raises_protocol_error(
            invalid_dispatch in arbitrary_invalid_dispatch_request(),
            valid_msg in any_server_to_client(),
        ) {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(prop_invalid_dispatch_raises_protocol_error_body(invalid_dispatch, valid_msg));
        }
    }

    async fn prop_handshake_ack_before_hello_body(
        does_send_hello_after_ack: bool,
        post_ack_msg: ServerToClient,
    ) {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let mut d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
        );

        let (mut client, mut server) = new_io_pair();

        // Derive some made up ID:
        let client_nonce = IdNonce::default();
        let server_nonce = IdNonce::default();
        let connection_id = ConnectionId::new(client_nonce.as_bytes(), server_nonce.as_bytes());

        assert_matches!(d.state, ConnState::PreHandshake);

        // Deliver the out-of-order ACK to the delegate:
        d.process(
            Ok(ServerToClient::ClientHelloAck {
                connection_id: UntrustedConnectionId::new(
                    Bytes::copy_from_slice(server_nonce.as_bytes()),
                    Bytes::copy_from_slice(connection_id.as_bytes()),
                ),
            }),
            &mut client,
        )
        .await;

        // The client MUST now report a protocol violation:
        let err = server.recv().await.expect("protocol violation notify");
        assert_matches!(err, ClientToServer::ProtocolError { reason, is_handshake_complete } => {
            assert!(!is_handshake_complete);
            assert_eq!(reason, ProtocolError::HandshakeAckBeforeHello);
        });

        // It transitions to the error state to uphold the subsequent checks:
        assert_matches!(d.state, ConnState::Error);

        // Simulate the delegate being asked to send the handshake after the ACK
        // by the caller - this helps explore and assert state transition
        // guards.
        if does_send_hello_after_ack {
            d.send_hello(&mut client).await;

            // Which has no effect:
            tokio::time::timeout(Duration::from_millis(50), server.recv())
                .await
                .expect_err("must timeout - no message expected");
        }

        // The client MUST now be in the error state, and ignore any further
        // messages from the server, no matter their content:
        d.process(Ok(post_ack_msg), &mut client).await;
        assert_matches!(server.recv().now_or_never(), None);

        // Remaining in the error state:
        assert_matches!(d.state, ConnState::Error);

        // Avoids errors in the FFI layer until the server closes the
        // connection.
        assert!(!server.is_connection_closed());
    }

    async fn prop_handshake_connection_id_rejected_body(
        server_nonce: [u8; 16],
        proposed_id: [u8; 16],
        post_error_msg: ServerToClient,
    ) {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let mut d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
        );

        // The initial state is "pre-handshake":
        assert_matches!(d.state, ConnState::PreHandshake);

        let (mut client, mut server) = new_io_pair();

        // Trigger the delegate to send the initial handshake message.
        d.send_hello(&mut client).await;

        // Which drives the state to "handshaking":
        assert_matches!(d.state, ConnState::Handshaking(..));

        // And sends the ClientHello.
        assert_matches!(
            server.recv().await,
            Some(ClientToServer::ClientHello { .. })
        );

        // Deliver the ACK containing a bogus ID:
        d.process(
            Ok(ServerToClient::ClientHelloAck {
                connection_id: UntrustedConnectionId::new(
                    Bytes::copy_from_slice(&server_nonce),
                    Bytes::copy_from_slice(&proposed_id),
                ),
            }),
            &mut client,
        )
        .await;

        // The client must now be in the error state:
        assert_matches!(d.state, ConnState::Error);

        // And should have notified the server of a protocol violation:
        assert_matches!(
            server.recv().await,
            Some(ClientToServer::ProtocolError {
                reason,
                is_handshake_complete
            }) => {
                assert!(!is_handshake_complete); // Incomplete
                assert_eq!(reason, ProtocolError::HandshakeConnectionIdRejected);
            }
        );

        // The client is now in the error state, and MUST ignore any further
        // messages from the server, no matter their content:
        d.process(Ok(post_error_msg), &mut client).await;
        assert_matches!(server.recv().now_or_never(), None);

        // Remaining in the error state:
        assert_matches!(d.state, ConnState::Error);

        // Avoids errors in the FFI layer until the server closes the
        // connection.
        assert!(!server.is_connection_closed());
    }

    async fn prop_handshake_duplicate_body(post_ack_msg: ServerToClient) {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let mut d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
        );

        let (mut client, mut server) = new_io_pair();

        // Drive a complete, successful handshake.
        do_handshake(&mut d, &mut client, &mut server).await;

        // Which completes the handshake for the client:
        assert_matches!(d.state, ConnState::Active(..));

        // Attempt a second delivery - the content is irrelevant, as an ACK
        // received in the Active state is rejected regardless:
        d.process(
            Ok(ServerToClient::ClientHelloAck {
                connection_id: UntrustedConnectionId::new(
                    Bytes::from_static(&[0; 16]),
                    Bytes::from_static(&[0; 16]),
                ),
            }),
            &mut client,
        )
        .await;

        // Which errors the client:
        assert_matches!(d.state, ConnState::Error);

        // Causing it to emit a protocol error:
        assert_matches!(
            server.recv().await,
            Some(ClientToServer::ProtocolError {
                reason,
                is_handshake_complete
            }) => {
                assert!(is_handshake_complete); // Completed!
                assert_eq!(reason, ProtocolError::HandshakeDuplicateAck);
            }
        );

        // The client is now in the error state, and MUST ignore any further
        // messages from the server, no matter their content:
        d.process(Ok(post_ack_msg), &mut client).await;
        assert_matches!(server.recv().now_or_never(), None);

        // Remaining in the error state:
        assert_matches!(d.state, ConnState::Error);

        // Avoids errors in the FFI layer until the server closes the
        // connection.
        assert!(!server.is_connection_closed());
    }

    async fn prop_message_types_allowed_during_handshake_body(
        pre_handshake: Option<ServerToClient>,
        during_handshake: Option<ServerToClient>,
        post_handshake: Option<ServerToClient>,
    ) {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let mut d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
        );

        let (mut client, mut server) = new_io_pair();

        // If the test has selected a pre-handshake message, send it (and
        // optionally drain any response it generates):
        if let Some(msg) = pre_handshake {
            let has_reply = has_reply(&msg);
            d.process(Ok(msg), &mut client).await;
            if has_reply {
                server.recv().await.expect("must reply");
            }
        }

        // Trigger the delegate to send the initial handshake message.
        d.send_hello(&mut client).await;

        // Verify the data provided in the handshake, and extract the nonce:
        let client_nonce = assert_matches!(
            server.recv().await,
            Some(ClientToServer::ClientHello {
                client_nonce,
                ..
            }) => client_nonce
        );

        // If the test has selected a during handshake message, send it (and
        // optionally drain any response it generates):
        if let Some(msg) = during_handshake {
            let has_reply = has_reply(&msg);
            d.process(Ok(msg), &mut client).await;
            if has_reply {
                server.recv().await.expect("must reply");
            }
        }

        // Derive the final connection ID:
        let server_nonce = IdNonce::default();
        let connection_id = ConnectionId::new(&client_nonce, server_nonce.as_bytes());

        // Deliver the ACK to the delegate:
        d.process(
            Ok(ServerToClient::ClientHelloAck {
                connection_id: UntrustedConnectionId::new(
                    Bytes::copy_from_slice(server_nonce.as_bytes()),
                    Bytes::copy_from_slice(connection_id.as_bytes()),
                ),
            }),
            &mut client,
        )
        .await;

        // If the test has selected a post-handshake message, send it (and
        // optionally drain any response it generates):
        if let Some(msg) = post_handshake {
            let has_reply = has_reply(&msg);
            d.process(Ok(msg), &mut client).await;
            if has_reply {
                server.recv().await.expect("must reply");
            }
        }

        // The client stays in the active connection state:
        assert_matches!(d.state, ConnState::Active(..));

        // And will respond to further requests:
        d.process(Ok(ServerToClient::Ping), &mut client).await;
        assert_matches!(server.recv().await, Some(ClientToServer::Pong));
    }

    async fn prop_any_message_after_handshake_body(msg: ServerToClient) {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let mut d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
        );

        let (mut client, mut server) = new_io_pair();

        // Drive a complete, successful handshake.
        do_handshake(&mut d, &mut client, &mut server).await;

        // Nothing further from the client:
        assert_matches!(server.recv().now_or_never(), None);

        // Deliver any message to the client:
        d.process(Ok(msg), &mut client).await;

        // The message is considered acceptable so long as the client stays in
        // the active connection state:
        assert_matches!(d.state, ConnState::Active(..));
    }

    async fn prop_deserialisation_error_rejects_messages_body(msg: ServerToClient) {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let mut d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
        );

        let (mut client, mut server) = new_io_pair();

        // Drive a complete, successful handshake.
        do_handshake(&mut d, &mut client, &mut server).await;

        // Nothing further from the client:
        assert_matches!(server.recv().now_or_never(), None);

        // Deliver a deserialisation error to the client:
        d.process(Err(DecodingError::NoMessage), &mut client).await;

        // Which should cause it to emit a protocol error:
        assert_matches!(
            server.recv().await,
            Some(ClientToServer::ProtocolError {
                reason,
                is_handshake_complete
            }) => {
                assert!(is_handshake_complete); // Complete
                assert_matches!(reason, ProtocolError::DeserialisationFailed(v) => {
                    assert_eq!(v, DecodingError::NoMessage.to_string());
                });
            }
        );

        // And transition to the error state:
        assert_matches!(d.state, ConnState::Error);

        // Causing it to reject all subsequent messages:
        d.process(Ok(msg), &mut client).await;

        assert_matches!(server.recv().now_or_never(), None);
        assert_matches!(d.state, ConnState::Error);
    }

    async fn prop_invalid_dispatch_raises_protocol_error_body(
        invalid_dispatch: ServerToClient,
        valid_msg: ServerToClient,
    ) {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let mut d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
        );

        let (mut client, mut server) = new_io_pair();

        // Drive a complete, successful handshake.
        do_handshake(&mut d, &mut client, &mut server).await;

        assert_matches!(d.state, ConnState::Active(..));

        // Deliver the invalid dispatch message:
        d.process(Ok(invalid_dispatch), &mut client).await;

        // Which should cause the client to emit a protocol violation error:
        let err = assert_matches!(
            server.recv().await,
            Some(ClientToServer::ProtocolError {
                reason,
                is_handshake_complete
            }) => {
                assert!(is_handshake_complete); // Complete
                reason
            }
        );

        // The violation can only be one of these variants:
        assert_matches!(
            err,
            ProtocolError::DispatchBeforeHandshake(..)
                | ProtocolError::DispatchMissingSignature(..)
                | ProtocolError::CertIdInvalidLength(..)
        );

        // The client MUST now be in the error state:
        assert_matches!(d.state, ConnState::Error);

        // Which causes it to refuse any subsequent valid message:
        d.process(Ok(valid_msg), &mut client).await;
        assert_matches!(server.recv().now_or_never(), None);
        assert_matches!(d.state, ConnState::Error);
    }
}
