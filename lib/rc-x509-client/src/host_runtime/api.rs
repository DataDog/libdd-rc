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

use futures::Stream;
use thiserror::Error;

use crate::codec::{ClientToServer, DecodingError, ServerToClient};

/// The runtime host has rejected a [`RustToHost::dispatch()`] call.
#[derive(Debug, Error)]
pub enum DispatchError {}

/// Message delivery errors reported by the runtime host.
///
/// These errors indicate that a message dispatched to the runtime host
/// ([`RustToHost::dispatch()`]) was not successfully delivered to the end
/// client that should process it (non-RC code).
#[derive(Debug, Error)]
pub enum InvokeError {}

/// Errors returned by the FFI host runtime when sending data.
#[derive(Debug, Error)]
pub enum ConnectionErr {
    /// Catch-all if the error reported by the host runtime does not map to one
    /// of the other variants.
    #[error("unknown connection error")]
    Unknown,

    /// The connection was marked as closed by the host runtime.
    #[error("connection is closed")]
    Closed,

    /// The outgoing payload queue is full.
    #[error("tx queue full")]
    QueueFull,
}

/// An abstract broker of I/O to the RC delivery backend.
pub trait Connection: std::fmt::Debug + Send + Sync + 'static {
    /// The type of incoming message stream provided by
    /// [`Self::take_recv_stream()`].
    type Incoming: Stream<Item = Result<ServerToClient, DecodingError>>
        + std::fmt::Debug
        + Send
        + Sync;

    /// Enqueue an outgoing message from this client library to the RC delivery
    /// backend for delivery.
    ///
    /// # Delivery Guarantees
    ///
    /// Payloads are sent by the host runtime in the order they are passed to
    /// this function. The host runtime asynchronously ends the payload, and
    /// provides no acknowledgement.
    ///
    /// If the send fails, the connection is eventually closed, and in-flight
    /// messages are lost.
    fn send(
        &mut self,
        payload: ClientToServer,
    ) -> impl Future<Output = Result<(), ConnectionErr>> + Send + Sync;

    /// Obtain the incoming stream of deserialised messages (or a corresponding
    /// deserialisation error) from the RC backend server.
    ///
    /// This call returns [`None`] if the stream has already been taken. The
    /// returned stream is closed when the connection is disconnected.
    ///
    /// # Delivery Guarantees
    ///
    /// Data received from the RC backend is returned by this function in the
    /// order it is read from the RC backend by the host runtime.
    fn take_recv_stream(&mut self) -> Option<Self::Incoming>;
}
