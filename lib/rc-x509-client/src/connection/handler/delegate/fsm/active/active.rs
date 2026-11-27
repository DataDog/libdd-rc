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

use std::fmt::Debug;

use rc_crypto::connection_id::ConnectionId;
use rc_crypto::{Signature, certificate::id::CertId};
use rc_x509_trust::cert::UntrustedCertBytes;
use tokio_util::bytes::Bytes;
use tracing::{debug, error, trace, warn};

use crate::{
    Payload,
    codec::{
        ClientToServer, DetachedSignature, DispatchViolation, HandshakeViolation, ProtocolError,
        ServerToClient,
    },
    connection::handler::{
        AttestationVerifier, SendToServer,
        delegate::{
            fsm::{
                Fsm, ServerMessageDelegate,
                active::verifier_state::{Deferred, DeferredVerifierState, VerifyFailure},
            },
            retry_send,
            state::State,
        },
    },
    dispatch::Dispatch,
    host_runtime::CorrelationId,
};

/// The handshake completed successfully, and the connection is fully ready to
/// process requests.
#[derive(Debug)]
pub(crate) struct Active {
    connection_id: ConnectionId,
    payload_verifier_state: DeferredVerifierState,
}

impl Active {
    pub(crate) fn new(connection_id: ConnectionId) -> Self {
        Self {
            connection_id,
            payload_verifier_state: DeferredVerifierState::default(),
        }
    }

    pub(crate) const IS_HANDSHAKE_COMPLETE: bool = true;
}

impl<IO, V> ServerMessageDelegate<IO, V> for Fsm<Active, V>
where
    IO: SendToServer,
    V: AttestationVerifier,
{
    const IS_HANDSHAKE_COMPLETE: bool = Active::IS_HANDSHAKE_COMPLETE;

    async fn send_hello(self, _reply: &mut IO) -> State<V> {
        unreachable!("send_hello called outside the pre-handshake phase")
    }

    async fn process(self, msg: ServerToClient, reply: &mut IO) -> State<V> {
        match msg {
            ServerToClient::Ping => {
                retry_send(reply, ClientToServer::Pong, &self.stop).await;
                State::Active(self)
            }

            ServerToClient::CertificatePush(certs) => self.handle_cert_push(reply, certs).await,

            ServerToClient::SetReconnectionData(..) => {
                // TODO: implement.
                State::Active(self)
            }

            ServerToClient::Dispatch {
                connection_id,
                correlation_id,
                payload,
                detached_signature,
            } => {
                self.handle_dispatch(
                    reply,
                    connection_id,
                    correlation_id,
                    payload,
                    detached_signature,
                )
                .await
            }

            // The client has already completed the handshake, so this ACK is
            // a duplicate.
            ServerToClient::ClientHelloAck { .. } => {
                self.protocol_error(
                    Active::IS_HANDSHAKE_COMPLETE,
                    reply,
                    ProtocolError::Handshake(HandshakeViolation::DuplicateAck),
                )
                .await
            }
        }
    }
}

impl<V> Fsm<Active, V>
where
    V: AttestationVerifier,
{
    /// Process a [`ServerToClient::Dispatch`] request, verifying the attached
    /// [`DetachedSignature`] before forwarding `payload` to the host
    /// application via [`DispatchPublisher`].
    ///
    /// This call deserialises all inputs and delegates processing to the
    /// [`DeferredVerifierState`], which is responsible for tracking any
    /// validations that cannot complete due to missing local certs, and
    /// resuming those validations when those certs become available.
    ///
    /// Ultimately, the [`AttestationVerifier`] impl performs the actual
    /// verification once all inputs are available.
    ///
    /// [`DispatchPublisher`]: crate::dispatch::DispatchPublisher
    async fn handle_dispatch<IO>(
        mut self,
        reply: &mut IO,
        request_connection_id: Bytes,
        correlation_id: CorrelationId,
        payload: Payload,
        detached_signature: Option<DetachedSignature>,
    ) -> State<V>
    where
        IO: SendToServer,
    {
        let connection_id = &self.state.connection_id;

        // Ensure the payload is targeted at this connection.
        if request_connection_id.as_ref() != connection_id.as_bytes() {
            error!(
                %connection_id,
                %correlation_id,
                ?request_connection_id,
                "dispatch request connection ID mismatch"
            );
            return self
                .protocol_error(
                    Active::IS_HANDSHAKE_COMPLETE,
                    reply,
                    ProtocolError::Dispatch(
                        correlation_id,
                        DispatchViolation::ConnectionIdMismatch,
                    ),
                )
                .await;
        }

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
                        ProtocolError::Dispatch(
                            correlation_id,
                            DispatchViolation::MissingSignature,
                        ),
                    )
                    .await;
            }
        };

        // Parse the signature from the raw bytes.
        let signature = match Signature::try_from(signature.as_ref()) {
            Ok(v) => v,
            Err(e) => {
                error!(error=%e, "invalid signature in dispatch request");
                return self
                    .protocol_error(
                        Active::IS_HANDSHAKE_COMPLETE,
                        reply,
                        ProtocolError::Dispatch(
                            correlation_id,
                            DispatchViolation::MalformedSignature(e.to_string()),
                        ),
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
                        ProtocolError::Dispatch(
                            correlation_id,
                            DispatchViolation::CertIdInvalidLength(got_len),
                        ),
                    )
                    .await;
            }
        };

        debug!(%connection_id, %correlation_id, %signing_cert_id, ?signature, "received dispatch request");

        // Perform all necessary chain and signature checks.
        let verify_ret = self.state.payload_verifier_state.verify_or_defer(
            &self.verifier,
            &self.endpoint_hostname,
            request_connection_id,
            correlation_id,
            signing_cert_id,
            signature,
            payload, // Moved, only returned if valid.
        );

        // Handle the verification result.
        //
        // Broadly speaking, this falls into one of three categories:
        //
        //  * Everything is fine, dispatch the payload.
        //  * A cert necessary for validation isn't known locally, fetch it.
        //  * Something is very, very wrong.
        //
        let payload = match verify_ret {
            // Everything is OK! Assign the "payload" to the outer var so it can
            // be dispatched below.
            Ok(payload) => payload,

            // A certificate that forms part of the chain from the root to the
            // leaf is missing, and it has the cert ID specified in
            // `missing_cert_id`.
            //
            // This cert (and potentially certs from the root to it) need to be
            // fetched from the backend before verification can complete.
            Err(VerifyFailure::MissingCert {
                missing_cert_id,
                deferred_count,
            }) => {
                debug!(
                    %missing_cert_id,
                    %deferred_count,
                    "deferring validation to resolve missing certificate"
                );

                // Request the server push the missing certificate (and the
                // chain to it) so the deferred verification can complete later.
                retry_send(
                    reply,
                    ClientToServer::ChainFetch {
                        cert_id: missing_cert_id,
                    },
                    &self.stop,
                )
                .await;

                return State::Active(self);
            }

            // Something is very wrong, and it's terminal:
            Err(VerifyFailure::Rejected(e)) => {
                // Fatal verification error (logged internally).
                return self
                    .protocol_error(Active::IS_HANDSHAKE_COMPLETE, reply, *e)
                    .await;
            }
        };

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

    /// Handle a cert push from the server.
    ///
    /// # Deferred Dispatch Validation
    ///
    /// In the happy path the server will be pushing certificates before they
    /// are needed, however if a dispatch has arrived that referenced a
    /// certificate that was not in the local cache, then this call will
    /// identify the deferred dispatches that were waiting on one of more of the
    /// pushed certs (if any) and resume their processing as part of this call.
    ///
    /// See the [`DeferredVerifierState`] for more details.
    pub(crate) async fn handle_cert_push<IO>(
        mut self,
        reply: &mut IO,
        certs: Vec<UntrustedCertBytes>,
    ) -> State<V>
    where
        IO: SendToServer,
        V: AttestationVerifier,
    {
        let deferred = match self
            .state
            .payload_verifier_state
            .add_certs(&self.verifier, certs)
        {
            Ok(Some(v)) => v,
            Ok(None) => {
                trace!("no deferred validations to complete");
                return State::Active(self);
            }
            Err(e) => {
                // Fatal verification error (logged internally).
                return self
                    .protocol_error(Active::IS_HANDSHAKE_COMPLETE, reply, *e)
                    .await;
            }
        };

        debug!(n=?deferred.size_hint(), "cert push unblocks deferred validations");

        for v in deferred {
            let Deferred {
                request_connection_id,
                correlation_id,
                signing_cert_id,
                signature,
                payload,
            } = v;

            // Invariant: any deferred verifications have already completed the
            // connection ID check, so all deferred verifications MUST be
            // referencing the correct connection ID.
            assert_eq!(
                request_connection_id.as_ref(),
                self.state.connection_id.as_bytes()
            );

            trace!(%correlation_id, "reverifying deferred payload");

            match self
                .handle_dispatch(
                    reply,
                    request_connection_id,
                    correlation_id,
                    payload,
                    Some(DetachedSignature {
                        cert_id: Bytes::copy_from_slice(
                            signing_cert_id.as_dangerous_comparable().as_bytes(),
                        ),
                        signature: Bytes::copy_from_slice(signature.as_ref()),
                    }),
                )
                .await
            {
                State::Active(fsm) => self = fsm,
                v => {
                    warn!("aborting deferred validations");
                    return v;
                }
            }

            trace!(%correlation_id, "deferred payload verification complete");
        }

        State::Active(self)
    }
}
