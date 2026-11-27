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

use std::{ops::Deref, time::Duration};

use assert_matches::assert_matches;
use rc_crypto::{
    Signature,
    certificate::{Certificate, id::CertId},
    connection_id::{ConnectionId, IdNonce, UntrustedConnectionId},
};
use rc_x509_client::{
    AbortOnDrop, EndpointHostname, Payload, ShutdownCtl,
    codec::{ClientToServer, DecodingError, DetachedSignature, ServerToClient},
    connection::{ConnectionEvent, ConnectionUpdate},
    dispatch::{
        Dispatch, DispatchError, DispatchResponder, DispatchResult, DispatchStream,
        new_dispatcher_interconnect,
    },
    host_runtime::CorrelationId,
};
use rc_x509_proto::{
    decode, encode,
    magic_tunnel::v1::{MagicTunnelRequest, MagicTunnelResponse, magic_tunnel_response},
    protocol::v1,
};
use rc_x509_trust::cert::UntrustedCertBytes;
use tokio::{sync::mpsc, time::timeout};
use tokio_stream::StreamExt;
use tokio_util::bytes::Bytes;

use crate::{
    TestClientBuilder,
    io::{MockIO, MockIOServer, new_io_pair},
};

/// A running instance of the client library, driven over a mocked transport.
#[derive(Debug)]
pub struct TestClient {
    handle: AbortOnDrop<()>,
    stop: ShutdownCtl,

    event_tx: mpsc::Sender<ConnectionUpdate<MockIO>>,
}

impl Default for TestClient {
    fn default() -> Self {
        TestClientBuilder::default().build()
    }
}

impl TestClient {
    /// See the [`TestClientBuilder`].
    pub(crate) fn new(
        handle: AbortOnDrop<()>,
        stop: ShutdownCtl,
        event_tx: mpsc::Sender<ConnectionUpdate<MockIO>>,
    ) -> Self {
        Self {
            handle,
            stop,
            event_tx,
        }
    }

    /// Register a new connection with the client, returning a handle to the
    /// connection.
    #[must_use]
    pub async fn new_connection(&mut self) -> TestConn {
        let (io, server) = new_io_pair();
        let (dispatch_publisher, dispatch_stream, dispatch_response) =
            new_dispatcher_interconnect();

        // Initialise the connection:
        self.event_tx
            .send(ConnectionUpdate::new(ConnectionEvent::Init))
            .await
            .expect("notify: connection init");

        // And signal it is ready for I/O to begin:
        self.event_tx
            .send(ConnectionUpdate::new(ConnectionEvent::Connected(
                io,
                dispatch_publisher,
                EndpointHostname::try_from("config.itsallbroken.com".to_string()).unwrap(),
            )))
            .await
            .expect("notify: connection connected");

        TestConn {
            io: server,
            dispatch_stream,
            dispatch_response,
            connection_id: None,
        }
    }

    /// Gracefully stop the client and wait for it to return.
    pub async fn shutdown(self) {
        self.stop.shutdown_now();

        let _: () = timeout(Duration::from_secs(5), self.handle.into_inner())
            .await
            .expect("graceful shutdown timeout")
            .expect("client panic");
    }
}

/// A connection to the client library.
#[derive(Debug)]
pub struct TestConn {
    io: MockIOServer,
    dispatch_stream: DispatchStream,
    dispatch_response: DispatchResponder,
    connection_id: Option<v1::ConnectionId>,
}

impl TestConn {
    /// Push `v` to the client over the mocked transport.
    pub async fn send(&mut self, v: Result<ServerToClient, DecodingError>) {
        self.io.send(v).await.expect("failed to send to client")
    }

    /// Push `certs` to the client's certificate cache, as the server would.
    ///
    /// Certificates are pushed as-is; the client is responsible for parsing
    /// and (eventually) validating them.
    pub async fn push_certs<'a>(&mut self, certs: impl IntoIterator<Item = &'a Certificate>) {
        self.send(Ok(ServerToClient::CertificatePush(
            certs
                .into_iter()
                .map(|c| UntrustedCertBytes::new(c.as_der()))
                .collect(),
        )))
        .await
    }

    /// Send `opaque` reconnection data to the client, as the server would.
    pub async fn set_reconnection_data(&mut self, opaque: Bytes) {
        let wire = encode(&v1::ServerToClient {
            message: Some(v1::server_to_client::Message::SetReconnectionData(
                v1::SetReconnectionData { opaque },
            )),
        });

        let data = assert_matches!(
            ServerToClient::try_from(wire.as_ref()),
            Ok(ServerToClient::SetReconnectionData(v)) => v
        );

        self.send(Ok(ServerToClient::SetReconnectionData(data)))
            .await;
    }

    /// Wait for the client to send a [`ClientToServer`].
    pub async fn recv(&mut self) -> TestClientToServer {
        TestClientToServer(self.io.recv().await.expect("failed to recv from client"))
    }

    /// Drive the [`ClientHello`]/[`ClientHelloAck`] handshake to completion,
    /// returning the derived connection ID.
    ///
    /// [`ClientHello`]: ClientToServer::ClientHello
    /// [`ClientHelloAck`]: ServerToClient::ClientHelloAck
    pub async fn perform_handshake(&mut self) -> ConnectionId {
        // Read the ClientHello and extract the nonce.
        let got = self.recv().await;
        let client_nonce = assert_matches!(
            got.into_inner(),
            ClientToServer::ClientHello {
                client_nonce,
                ..
            } => client_nonce
        );

        // Derive the final connection ID:
        let server_nonce = IdNonce::default();
        let connection_id = ConnectionId::new(&client_nonce, server_nonce.as_bytes());

        // Deliver the ACK to the client, including the validly derived
        // connection ID it should accept.
        self.send(Ok(ServerToClient::ClientHelloAck {
            connection_id: UntrustedConnectionId::new(
                Bytes::copy_from_slice(server_nonce.as_bytes()),
                Bytes::copy_from_slice(connection_id.as_bytes()),
            ),
        }))
        .await;

        self.connection_id = Some(conn_id_to_proto(connection_id.clone()));

        connection_id
    }

    /// Simulate the server sending a dispatch request for `uri` with
    /// `request`, correlated by `correlation_id`.
    ///
    /// The connection handshake must have been performed first.
    pub async fn dispatch_magic_tunnel(
        &mut self,
        correlation_id: CorrelationId,
        signer_cert_id: &CertId,
        signature: Signature,
        uri: &str,
        request: Bytes,
    ) {
        let connection_id = self
            .connection_id
            .clone()
            .expect("handshake must be performed before dispatching");

        let payload = Payload::from(encode(&v1::DispatchRequestPayload {
            connection_id: Some(connection_id.clone()),
            payload: Some(v1::dispatch_request_payload::Payload::MagicTunnel(
                MagicTunnelRequest {
                    uri: uri.to_string(),
                    request,
                },
            )),
        }));

        self.send(Ok(ServerToClient::Dispatch {
            connection_id: connection_id.uuid_v8.clone(),
            correlation_id,
            payload,
            detached_signature: Some(DetachedSignature {
                cert_id: Bytes::copy_from_slice(
                    signer_cert_id.as_dangerous_comparable().as_bytes(),
                ),
                signature: Bytes::copy_from_slice(signature.as_ref()),
            }),
        }))
        .await;
    }

    /// Wait for the client to route a dispatch request to the application.
    pub async fn get_application_dispatch(&mut self) -> TestDispatch {
        let dispatch = tokio::time::timeout(Duration::from_secs(5), self.dispatch_stream.next())
            .await
            .expect("timeout waiting for app dispatch")
            .expect("dispatch stream must be running");

        TestDispatch {
            dispatch,
            responder: self.dispatch_response.clone(),
        }
    }

    /// Close this connection.
    pub async fn close(self) {
        drop(self)
    }
}

/// A [`ClientToServer`] message received from the client, with helper
/// methods for asserting on common message shapes.
#[derive(Debug)]
pub struct TestClientToServer(ClientToServer);

impl TestClientToServer {
    /// Unwrap this into the underlying [`ClientToServer`] message, for use
    /// with pattern matching that must own the message (i.e. extracts
    /// non-[`Copy`] fields).
    pub fn into_inner(self) -> ClientToServer {
        self.0
    }

    /// Assert this is a [`ClientToServer::DispatchResponse`] correlated by
    /// `correlation_id`, carrying a [`MagicTunnel`] response, and return its
    /// result.
    ///
    /// [`MagicTunnel`]: v1::dispatch_response_payload::Payload::MagicTunnel
    pub fn assume_magic_tunnel_response(
        self,
        correlation_id: CorrelationId,
    ) -> magic_tunnel_response::Result {
        let result = assert_matches!(
            self.into_inner(),
            ClientToServer::DispatchResponse { correlation_id: got_id, result } => {
                assert_eq!(got_id, correlation_id);
                result
            }
        );

        let magic_tunnel_response = assert_matches!(
            result,
            v1::dispatch_response::Result::Payload(v1::DispatchResponsePayload {
                payload: Some(v1::dispatch_response_payload::Payload::MagicTunnel(v)),
            }) => v
        );

        magic_tunnel_response
            .result
            .expect("magic tunnel response must carry a result")
    }
}

impl Deref for TestClientToServer {
    type Target = ClientToServer;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A [`Dispatch`] request routed to the application, with helper methods for
/// asserting on and responding to it.
#[derive(Debug)]
pub struct TestDispatch {
    dispatch: Dispatch,
    responder: DispatchResponder,
}

impl TestDispatch {
    /// The correlation ID this dispatch request must be responded with.
    pub fn correlation_id(&self) -> CorrelationId {
        self.dispatch.correlation_id
    }

    /// The raw application payload carried by this dispatch request.
    pub fn payload(&self) -> &Payload {
        &self.dispatch.payload
    }

    /// Decode this dispatch's payload, asserting it was routed for
    /// `connection_id` and is a [`MagicTunnel`] request, and return its
    /// uri and application payload.
    ///
    /// [`MagicTunnel`]: v1::dispatch_request_payload::Payload::MagicTunnel
    pub fn assume_magic_tunnel(&self, connection_id: &v1::ConnectionId) -> (String, Bytes) {
        let got: v1::DispatchRequestPayload =
            decode(self.payload().as_bytes().clone()).expect("valid message");

        assert_matches!(got.connection_id, Some(id) => {
            assert_eq!(&id, connection_id);
        });

        let magic_tunnel_request = assert_matches!(
            got.payload,
            Some(v1::dispatch_request_payload::Payload::MagicTunnel(v)) => v
        );

        (magic_tunnel_request.uri, magic_tunnel_request.request)
    }

    /// Respond to this dispatch request with `result`.
    pub async fn respond(self, result: Result<v1::DispatchResponsePayload, DispatchError>) {
        self.responder
            .send_response(DispatchResult {
                correlation_id: self.correlation_id(),
                result,
            })
            .await
            .expect("must respond to dispatch")
    }

    /// Respond to this dispatch with a magic tunnel response carrying
    /// `result`.
    pub async fn respond_magic_tunnel(self, result: magic_tunnel_response::Result) {
        self.respond(Ok(v1::DispatchResponsePayload {
            payload: Some(v1::dispatch_response_payload::Payload::MagicTunnel(
                MagicTunnelResponse {
                    result: Some(result),
                },
            )),
        }))
        .await
    }
}

/// Convert `c` into its protocol wire representation.
pub fn conn_id_to_proto(c: ConnectionId) -> v1::ConnectionId {
    v1::ConnectionId {
        uuid_v8: Bytes::copy_from_slice(c.as_bytes()),
    }
}
