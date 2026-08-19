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
    codec::{ClientToServer, ServerToClient},
    host_runtime::{Connection, ConnectionErr},
};

/// A [`ServerToClient`] message processor.
///
/// The implementation can dispatch any number of responses to the server via
/// the `reply` handle.
pub(super) trait ServerMessageDelegate<IO: SendToServer>: Debug + Send + Sync {
    /// Process the request in `msg`.
    fn process(
        &mut self,
        msg: ServerToClient,
        reply: &mut IO,
    ) -> impl Future<Output = ()> + Send + Sync;
}

/// A subtype of a [`Connection`] implementation, capable of sending responses
/// to the server only.
///
/// This trait is automatically implemented for all [`Connection`]
/// implementations.
pub(super) trait SendToServer: Debug + Send + Sync {
    /// Attempt to push `reply` to the server.
    fn send(
        &mut self,
        reply: ClientToServer,
    ) -> impl Future<Output = Result<(), ConnectionErr>> + Send + Sync;
}

impl<T> SendToServer for T
where
    T: Connection,
{
    async fn send(&mut self, reply: ClientToServer) -> Result<(), ConnectionErr> {
        T::send(self, reply).await
    }
}
