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

use tokio_util::sync::CancellationToken;
use tracing::{trace, warn};

use crate::{
    codec::{ClientToServer, ProtocolError},
    connection::handler::{
        SendToServer,
        delegate::{retry_send, state::State},
    },
    dispatch::DispatchPublisher,
    metrics::InstanceMetrics,
};

use super::Error;

/// A single lifecycle phase of a connection, generic over the phase-specific
/// `state`.
#[derive(Debug)]
pub(crate) struct Fsm<S> {
    pub(super) metrics: Arc<InstanceMetrics>,
    pub(super) stop: CancellationToken,
    pub(super) dispatch: DispatchPublisher,

    pub(super) state: S,
}

impl<S> Fsm<S>
where
    S: Debug,
{
    /// Transition to a new FSM state.
    pub(super) fn into_state<U>(self, state: U) -> Fsm<U>
    where
        U: Debug,
    {
        trace!(from=?self.state, to=?state, "fsm transition");

        Fsm {
            metrics: self.metrics,
            stop: self.stop,
            dispatch: self.dispatch,
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
    ) -> State
    where
        IO: SendToServer,
    {
        warn!(error = ?reason, "protocol error");

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
}
