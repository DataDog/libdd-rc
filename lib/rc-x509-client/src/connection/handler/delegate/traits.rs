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

use crate::{
    codec::ServerToClient,
    connection::handler::{SendToServer, delegate::state::State},
};

/// A state machine that processes [`ServerToClient`] messages.
///
/// Each implementation consumes `self` and returns the (possibly different)
/// next [`State`].
pub(crate) trait ServerMessageDelegate<IO>: Debug + Send + Sync + Sized
where
    IO: SendToServer,
{
    /// Send a `ClientHello` handshake message.
    ///
    /// # Panics
    ///
    /// Panics if this is not the first call to `self` (the state machine).
    fn send_hello(self, reply: &mut IO) -> impl Future<Output = State> + Send + Sync;

    /// Process the decoded `msg`.
    fn process(
        self,
        msg: ServerToClient,
        reply: &mut IO,
    ) -> impl Future<Output = State> + Send + Sync;
}
