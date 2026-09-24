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

use tracing::debug;

use crate::connection::handler::SendToServer;
use crate::{codec::ServerToClient, connection::handler::delegate::state::State};

use super::{Fsm, ServerMessageDelegate};

/// The connection has experienced a protocol error and all future messages
/// are ignored - see the module documentation for details.
#[derive(Debug)]
pub(crate) struct Error;

impl Error {
    /// This may not be true, but it is the least wrong - a completed handshake
    /// will not suddenly undo itself. It's also never reported, because no
    /// further protocol violations can occur.
    pub(crate) const IS_HANDSHAKE_COMPLETE: bool = true;
}

impl<IO> ServerMessageDelegate<IO> for Fsm<Error>
where
    IO: SendToServer,
{
    async fn send_hello(self, _reply: &mut IO) -> State {
        unreachable!("send_hello called outside the pre-handshake phase")
    }

    async fn process(self, _msg: ServerToClient, _reply: &mut IO) -> State {
        debug!("dropping message due to protocol error");
        State::Error(self)
    }
}
