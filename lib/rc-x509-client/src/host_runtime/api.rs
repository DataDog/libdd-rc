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

use crate::{
    codec::{ClientToServer, DecodingError, ServerToClient},
    host_runtime::CorrelationId,
    payload::PayloadTopic,
};

#[derive(Debug, Error)]
pub(crate) enum DialError {}

#[derive(Debug, Error)]
pub(crate) enum DispatchError {}

#[derive(Debug, Error)]
pub(crate) enum InvokeError {}

/// Errors returned by the FFI host runtime when sending data.
#[derive(Debug, Error)]
pub(crate) enum ConnectionErr {
    #[error("unknown connection error")]
    Unknown,

    #[error("connection is closed")]
    Closed,

    /// The outgoing payload queue is full.
    #[error("tx queue full")]
    QueueFull,
}

/// Boundary layer between calls from this library, to some abstract
/// implementation that can perform I/O and consume verified messages from RC.
///
/// ```text
///
///                                Go Program
///
///                                     ▲
///                                     │
///                             ┌──────────────┐
///                             │   FFI Impl   │
///                             └──────────────┘
///                                     ▲
///                                     │
///                             ╔══════════════╗
///                             ║  RustToHost  ║
///                             ╚══════════════╝
///                                     ▲
///                                     │
///
///                              Client Library
///
/// ```
///
/// This layer presents a rust API, with the FFI implementation of this trait
/// responsible for performing all conversions between rust types and their FFI
/// representations, encapsulating any unsafe operations.
pub(crate) trait RustToHost: std::fmt::Debug + Send + Sync + 'static {
    /// Call into the host message dispatcher to pass a verified `msg` to the
    /// registered client for `topic`. The call return value is later passed
    /// back providing the same unique `correlation_id`.
    ///
    /// MAY be called concurrently, MUST NOT block (expected return time is
    /// sub-millisecond).
    fn dispatch(
        &self,
        topic: PayloadTopic,
        msg: Vec<u8>,
        correlation_id: CorrelationId,
    ) -> Result<(), DispatchError>;
}

/// Callbacks from some abstract I/O provider and message processor.
///
/// ```text
///
///                                Go Program
///
///                                     │
///                                     ▼
///                             ┌──────────────┐
///                             │   FFI Impl   │
///                             └──────────────┘
///                                     │
///                                     ▼
///                             ╔══════════════╗
///                             ║  HostToRust  ║
///                             ╚══════════════╝
///                                     │
///                                     ▼
///
///                              Client Library
///
/// ```
///
/// This layer presents a rust API, with the FFI implementation of this trait
/// responsible for performing all conversions between rust types and their FFI
/// representations, encapsulating any unsafe operations.
pub(crate) trait HostToRust: std::fmt::Debug + Send + Sync + 'static {
    /// The concrete type of the host connection broker.
    type Connection: Connection;

    /// Connect to the RC backend, returning a [`Connection`] that brokers I/O
    /// with the host runtime.
    fn connect(&mut self) -> Result<Self::Connection, DialError>;

    /// A `dispatch()` has completed, and the handler returned the provided byte
    /// response.
    ///
    /// If a fatal system error occurred (such as the handler panicking) that
    /// prevented the client from returning a value itself, then an
    /// `InvokeError` enum is returned describing the failure (vs. a client
    /// returning an error is a successful response).
    fn dispatch_complete(
        &mut self,
        correlation_id: CorrelationId,
        response: Result<Vec<u8>, InvokeError>,
    );
}

/// An abstract broker of I/O to the RC delivery backend.
pub(crate) trait Connection: std::fmt::Debug + Send + Sync + 'static {
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
    async fn send(&mut self, payload: ClientToServer) -> Result<(), ConnectionErr>;

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
