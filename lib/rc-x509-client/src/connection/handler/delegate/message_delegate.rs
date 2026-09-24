use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    codec::{DecodingError, ProtocolError, ServerToClient},
    connection::handler::{SendToServer, ServerMessageDelegate, delegate::state::State},
    dispatch::DispatchPublisher,
    metrics::InstanceMetrics,
};

use super::fsm;

/// Handler for [`ServerToClient`] messages (an implementation of
/// [`ServerMessageDelegate`]).
#[derive(Debug)]
pub(crate) struct MessageDelegate(State);

impl MessageDelegate {
    pub(crate) fn new(
        stop: CancellationToken,
        metrics: Arc<InstanceMetrics>,
        dispatch: DispatchPublisher,
        client_name: String,
        client_version: String,
    ) -> Self {
        Self(State::PreHandshake(fsm::Fsm::new(
            metrics,
            stop,
            dispatch,
            client_name,
            client_version,
        )))
    }

    /// Process `msg`, reporting any deserialisation error to the server and
    /// otherwise dispatching to the current phase.
    async fn process_impl<IO>(
        state: State,
        msg: Result<ServerToClient, DecodingError>,
        reply: &mut IO,
    ) -> State
    where
        IO: SendToServer,
    {
        // If the connection has been marked as having experienced a protocol
        // error, all further messages are dropped. This client is waiting for
        // the server to close the connection.
        if let State::Error(s) = state {
            debug!("dropping message due to protocol error");
            return State::Error(s);
        }

        // Report any deserialisation errors to the server.
        let msg = match msg {
            Ok(v) => v,
            Err(e) => {
                warn!(error=%e, "dropping invalid message from server");

                return state
                    .protocol_error(reply, ProtocolError::DeserialisationFailed(e.to_string()))
                    .await;
            }
        };

        state.process(msg, reply).await
    }

    /// Returns the current lifecycle state.
    #[cfg(test)]
    pub(super) fn state(&self) -> &State {
        &self.0
    }
}

impl<IO> ServerMessageDelegate<IO> for MessageDelegate
where
    IO: SendToServer,
{
    async fn send_hello(self, reply: &mut IO) -> Self {
        Self(self.0.send_hello(reply).await)
    }

    async fn process(self, msg: Result<ServerToClient, DecodingError>, reply: &mut IO) -> Self {
        Self(Self::process_impl(self.0, msg, reply).await)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use futures::FutureExt;
    use proptest::prelude::*;
    use rc_crypto::connection_id::{ConnectionId, IdNonce, UntrustedConnectionId};
    use tokio_util::bytes::Bytes;

    use crate::{
        build_version::BuildVersion,
        codec::ClientToServer,
        connection::handler::delegate::fsm::test_helpers::{
            any_server_to_client, arbitrary_invalid_dispatch_request, do_handshake,
            filter_allowed_after_handshake, filter_allowed_at_any_time, filter_implemented,
            has_reply,
        },
        dispatch::new_dispatcher_interconnect,
        mocks::io::new_io_pair,
    };

    use super::*;

    /// Test handling of a PING server message.
    #[tokio::test]
    async fn test_ping_pong() {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
            "bananas".to_string(),
            "1.0.0".to_string(),
        );

        let (mut client, mut server) = new_io_pair();

        d.process(Ok(ServerToClient::Ping), &mut client).await;

        let got = server.recv().await.expect("must reply");
        assert_matches!(got, ClientToServer::Pong);
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
            "bananas".to_string(),
            "1.0.0".to_string(),
        );

        // The initial state is "pre-handshake":
        assert_matches!(d.state(), State::PreHandshake(..));

        let (mut client, mut server) = new_io_pair();

        // Trigger the delegate to send the initial handshake message.
        d = d.send_hello(&mut client).await;

        // Which drives the state to "handshaking":
        assert_matches!(d.state(), State::Handshaking(..));

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
                assert_eq!(app_name, "bananas");
                assert_eq!(client_nonce.len(), 16); // 128 bits of randomness.

                client_nonce
            }
        );

        // Derive the final connection ID:
        let server_nonce = IdNonce::default();
        let connection_id = ConnectionId::new(&client_nonce, server_nonce.as_bytes());

        // Deliver the ACK to the delegate:
        d = d
            .process(
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
        assert_matches!(d.state(), State::Active(..));
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
            "bananas".to_string(),
            "1.0.0".to_string(),
        );

        let (mut client, mut server) = new_io_pair();

        d = d.process(Err(DecodingError::NoMessage), &mut client).await;

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

        assert_matches!(d.state(), State::Error(..));
    }

    proptest! {
        /// Assert that a message that causes a deserialisation error causes the
        /// client to report a protocol error and refuse subsequent messages,
        /// even once the handshake has completed.
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

        /// Deliver a ClientHelloAck before the client sends the ClientHello,
        /// and ensure a protocol error is reported.
        ///
        /// Assert all subsequent messages from the server are ignored.
        #[test]
        fn prop_handshake_ack_before_hello(
            post_ack_msg in any_server_to_client(),
        ) {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(prop_handshake_ack_before_hello_body(post_ack_msg));
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
            pre_handshake in proptest::option::of(filter_allowed_at_any_time(any_server_to_client())),
            during_handshake in proptest::option::of(filter_allowed_at_any_time(any_server_to_client())),
            post_handshake in proptest::option::of(filter_allowed_at_any_time(any_server_to_client())),
        ) {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(prop_message_types_allowed_during_handshake_body(pre_handshake, during_handshake, post_handshake));
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
    }

    async fn prop_deserialisation_error_rejects_messages_body(msg: ServerToClient) {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let mut d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
            "bananas".to_string(),
            "1.0.0".to_string(),
        );

        let (mut client, mut server) = new_io_pair();

        // Drive a complete, successful handshake.
        d = do_handshake(d, &mut client, &mut server).await;

        // Nothing further from the client:
        assert_matches!(server.recv().now_or_never(), None);

        // Deliver a deserialisation error to the client:
        d = d.process(Err(DecodingError::NoMessage), &mut client).await;

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
        assert_matches!(d.state(), State::Error(..));

        // Causing it to reject all subsequent messages:
        d = d.process(Ok(msg), &mut client).await;

        assert_matches!(server.recv().now_or_never(), None);
        assert_matches!(d.state(), State::Error(..));
    }

    async fn prop_handshake_ack_before_hello_body(post_ack_msg: ServerToClient) {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let mut d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
            "bananas".to_string(),
            "1.0.0".to_string(),
        );

        let (mut client, mut server) = new_io_pair();

        // Derive some made up ID:
        let client_nonce = IdNonce::default();
        let server_nonce = IdNonce::default();
        let connection_id = ConnectionId::new(client_nonce.as_bytes(), server_nonce.as_bytes());

        assert_matches!(d.state(), State::PreHandshake(..));

        // Deliver the out-of-order ACK to the delegate:
        d = d
            .process(
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
        assert_matches!(d.state(), State::Error(..));

        // The client MUST now be in the error state, and ignore any further
        // messages from the server, no matter their content:
        d = d.process(Ok(post_ack_msg), &mut client).await;
        assert_matches!(server.recv().now_or_never(), None);

        // Remaining in the error state:
        assert_matches!(d.state(), State::Error(..));

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
            "bananas".to_string(),
            "1.0.0".to_string(),
        );

        let (mut client, mut server) = new_io_pair();

        // Drive a complete, successful handshake.
        d = do_handshake(d, &mut client, &mut server).await;

        // Which completes the handshake for the client:
        assert_matches!(d.state(), State::Active(..));

        // Attempt a second delivery - the content is irrelevant, as an ACK
        // received in the Active state is rejected regardless:
        d = d
            .process(
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
        assert_matches!(d.state(), State::Error(..));

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
        d = d.process(Ok(post_ack_msg), &mut client).await;
        assert_matches!(server.recv().now_or_never(), None);

        // Remaining in the error state:
        assert_matches!(d.state(), State::Error(..));

        // Avoids errors in the FFI layer until the server closes the
        // connection.
        assert!(!server.is_connection_closed());
    }

    async fn prop_any_message_after_handshake_body(msg: ServerToClient) {
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();
        let mut d = MessageDelegate::new(
            CancellationToken::default(),
            Arc::new(InstanceMetrics::default()),
            dispatch_publish,
            "bananas".to_string(),
            "1.0.0".to_string(),
        );

        let (mut client, mut server) = new_io_pair();

        // Drive a complete, successful handshake.
        d = do_handshake(d, &mut client, &mut server).await;

        // Nothing further from the client:
        assert_matches!(server.recv().now_or_never(), None);

        // Deliver any message to the client:
        d = d.process(Ok(msg), &mut client).await;

        // The message is considered acceptable so long as the client stays in
        // the active connection state:
        assert_matches!(d.state(), State::Active(..));
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
            "bananas".to_string(),
            "1.0.0".to_string(),
        );

        let (mut client, mut server) = new_io_pair();

        // Drive a complete, successful handshake.
        d = do_handshake(d, &mut client, &mut server).await;

        assert_matches!(d.state(), State::Active(..));

        // Deliver the invalid dispatch message:
        d = d.process(Ok(invalid_dispatch), &mut client).await;

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
        assert_matches!(d.state(), State::Error(..));

        // Which causes it to refuse any subsequent valid message:
        d = d.process(Ok(valid_msg), &mut client).await;
        assert_matches!(server.recv().now_or_never(), None);
        assert_matches!(d.state(), State::Error(..));
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
            "bananas".to_string(),
            "1.0.0".to_string(),
        );

        // The initial state is "pre-handshake":
        assert_matches!(d.state(), State::PreHandshake(..));

        let (mut client, mut server) = new_io_pair();

        // Trigger the delegate to send the initial handshake message.
        d = d.send_hello(&mut client).await;

        // Which drives the state to "handshaking":
        assert_matches!(d.state(), State::Handshaking(..));

        // And sends the ClientHello.
        assert_matches!(
            server.recv().await,
            Some(ClientToServer::ClientHello { .. })
        );

        // Deliver the ACK containing a bogus ID:
        d = d
            .process(
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
        assert_matches!(d.state(), State::Error(..));

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
        d = d.process(Ok(post_error_msg), &mut client).await;
        assert_matches!(server.recv().now_or_never(), None);

        // Remaining in the error state:
        assert_matches!(d.state(), State::Error(..));

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
            "bananas".to_string(),
            "1.0.0".to_string(),
        );

        let (mut client, mut server) = new_io_pair();

        // If the test has selected a pre-handshake message, send it (and
        // optionally drain any response it generates):
        if let Some(msg) = pre_handshake {
            let has_reply = has_reply(&msg);
            d = d.process(Ok(msg), &mut client).await;
            if has_reply {
                server.recv().await.expect("must reply");
            }
        }

        // Trigger the delegate to send the initial handshake message.
        d = d.send_hello(&mut client).await;

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
            d = d.process(Ok(msg), &mut client).await;
            if has_reply {
                server.recv().await.expect("must reply");
            }
        }

        // Derive the final connection ID:
        let server_nonce = IdNonce::default();
        let connection_id = ConnectionId::new(&client_nonce, server_nonce.as_bytes());

        // Deliver the ACK to the delegate:
        d = d
            .process(
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
            d = d.process(Ok(msg), &mut client).await;
            if has_reply {
                server.recv().await.expect("must reply");
            }
        }

        // The client stays in the active connection state:
        assert_matches!(d.state(), State::Active(..));

        // And will respond to further requests:
        d.process(Ok(ServerToClient::Ping), &mut client).await;
        assert_matches!(server.recv().await, Some(ClientToServer::Pong));
    }
}
