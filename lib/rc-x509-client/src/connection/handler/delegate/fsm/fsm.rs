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

use std::{fmt::Debug, sync::Arc};

use rc_x509_trust::{EndpointHostname, cert::UntrustedCertBytes};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, trace, warn};

use crate::{
    codec::{ClientToServer, ProtocolError},
    connection::{
        AttestationVerifier,
        handler::{
            SendToServer,
            delegate::{fsm::ServerMessageDelegate, retry_send, state::State},
        },
    },
    dispatch::DispatchPublisher,
    instance_state::InstanceState,
};

use super::Error;

/// A single lifecycle phase of a connection, generic over the phase-specific
/// `state`.
#[derive(Debug)]
pub(crate) struct Fsm<S, V> {
    pub(super) instance_state: Arc<InstanceState>,
    pub(super) stop: CancellationToken,
    pub(super) dispatch: DispatchPublisher,

    /// An abstract [`AttestationVerifier`] capable of validating a
    /// cryptographic signature covering a message from the backend.
    ///
    /// [`AttestationVerifier`]:
    ///     crate::connection::handler::delegate::traits::AttestationVerifier
    pub(super) verifier: V,
    /// The [`EndpointHostname`] passed to the verifier to enforce the DC pin.
    pub(super) endpoint_hostname: EndpointHostname,

    pub(super) state: S,
}

impl<S, V> Fsm<S, V>
where
    S: Debug,
{
    /// Transition to a new FSM state.
    pub(super) fn into_state<U>(self, state: U) -> Fsm<U, V>
    where
        U: Debug,
    {
        trace!(from=?self.state, to=?state, "fsm transition");

        Fsm {
            instance_state: self.instance_state,
            stop: self.stop,
            dispatch: self.dispatch,
            verifier: self.verifier,
            endpoint_hostname: self.endpoint_hostname,
            state,
        }
    }

    /// Log and report a protocol error `reason` to the backend, and
    /// transition to the terminal [`Error`] phase.
    pub(crate) async fn protocol_error<IO>(
        self,
        is_handshake_complete: bool,
        io: &mut IO,
        reason: ProtocolError,
    ) -> State<V>
    where
        IO: SendToServer,
    {
        warn!(
            error = ?reason,
            endpoint_hostname = %self.endpoint_hostname,
            "protocol error"
        );

        retry_send(
            io,
            ClientToServer::ProtocolError {
                reason,
                is_handshake_complete,
            },
            &self.stop,
        )
        .await;

        State::Error(self.into_state(Error))
    }

    /// Locally cache raw DER certificates (untrusted!) from the server.
    ///
    /// This is called only when the FSM is not in a state where there are
    /// deferred validations to complete (e.g. in the handshaking state)
    pub(crate) async fn handle_cert_push_ignore_deferred<IO>(
        self,
        reply: &mut IO,
        certs: Vec<UntrustedCertBytes>,
    ) -> State<V>
    where
        IO: SendToServer,
        V: AttestationVerifier,
        Self: ServerMessageDelegate<IO, V>,
        State<V>: From<Self>,
    {
        let certs = certs
            .into_iter()
            .map(UntrustedCertBytes::parse)
            .collect::<Result<Vec<_>, _>>();

        match certs {
            Ok(v) => {
                debug!(n = v.len(), "processing batched cert push");

                self.verifier.add(v.into_iter());

                State::from(self)
            }
            Err(e) => {
                error!(error=%e, "failed to parse certificate");

                self.protocol_error(
                    <Self as ServerMessageDelegate<IO, V>>::IS_HANDSHAKE_COMPLETE,
                    reply,
                    ProtocolError::CertPush(crate::codec::CertPushViolation::InvalidDer(
                        e.to_string(),
                    )),
                )
                .await
            }
        }
    }

    /// Return the connected [`EndpointHostname`] this FSM is using to verify
    /// against.
    pub(crate) fn endpoint_hostname(&self) -> &EndpointHostname {
        &self.endpoint_hostname
    }
}
