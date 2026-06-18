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

//! Payload passing layer, bridging from the client library into the application
//! host.

use futures::Stream;
use pin_project::pin_project;
use rc_x509_proto::{DecodeError, protocol::v1};
use thiserror::Error;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio_stream::wrappers::ReceiverStream;

use crate::host_runtime::CorrelationId;

/// The maximum number of dispatch payloads that can be queued in memory,
/// waiting for the [`DispatchSubscriber`] to consume.
///
/// Payload sizes are limited by the server, meaning the combination of server
/// limit and this queue bounds caps the amount of memory used by this queue.
///
/// This also bounds the [`DispatchResult`] queue, to this value + 1. Responses
/// SHOULD be generated one-to-one to dispatch requests.
const DISPATCH_QUEUE_LEN: usize = 255;

/// A payload to pass to the host application for further processing.
#[derive(Debug)]
pub struct Dispatch {
    /// The request correlation ID the host application should reference when
    /// returning a [`DispatchResult`].
    pub correlation_id: CorrelationId,

    /// The attestation-verified dispatch payload.
    pub payload: v1::dispatch_request::Payload,
}

/// The result of processing a [`Dispatch`].
///
/// Exactly one [`DispatchResult`] should be returned for each [`Dispatch`].
#[derive(Debug)]
pub struct DispatchResult {
    /// The [`CorrelationId`] in the original [`Dispatch`].
    pub correlation_id: CorrelationId,

    /// The result of the dispatch call.
    ///
    /// The result is split into:
    ///
    ///   * Failed dispatches; the payload is not delivered to any handler. This
    ///     results in a [`DispatchError`] being returned, and indicates the
    ///     current state of the system cannot handle the message sent.
    ///
    ///   * The message was delivered to a handler; this returns a
    ///     [`v1::dispatch_response::Result`] which may contain a handler
    ///     (application-level) error.
    ///
    pub result: Result<v1::DispatchResponsePayload, DispatchError>,
}

/// Failures to deliver a message to a handler.
#[derive(Debug, Error)]
pub enum DispatchError {
    /// The client does not support the payload type being dispatched.
    #[error("unknown payload type")]
    UnknownPayload,

    /// The client supports the type of payload being sent, but there is no
    /// handler registered to process it.
    #[error("no handler registered for the dispatched payload type")]
    NoDispatchHandler,

    /// The dispatch handler delivery queue is full.
    ///
    /// This occurs when the dispatch handler is not consuming messages fast
    /// enough to keep up with the rate of new requests arriving. The message
    /// will not be delivered.
    #[error("dispatch handler delivery queue is full")]
    HandlerQueueFull,

    /// An internal error that is returned when the dispatch thread's work queue
    /// is full of pending dispatch payloads.
    ///
    /// This indicates the dispatcher thread is too slow or blocked entirely.
    #[error("dispatch request queue is full")]
    DispatchRequestQueueFull,

    /// No messages can be dispatched to the host application because the
    /// dispatch thread has exited. This is a fatal state.
    #[error("dispatch task is not running")]
    DispatchClosed,

    /// An error deserialising the response from the host application.
    #[error("deserialisation error processing dispatch result from FFI host: {0}")]
    ReplyDeserialisation(DecodeError),

    /// Catch-all if the FFI layer returns an unknown error code.
    #[error("unknown dispatch error")]
    UnknownError,
}

/// A handle to publish [`Dispatch`] requests to the host application and
/// receive [`DispatchResult`] responses.
#[derive(Debug)]
pub struct DispatchPublisher {
    tx: mpsc::Sender<Dispatch>,
    rx: Option<mpsc::Receiver<DispatchResult>>,
}

impl DispatchPublisher {
    /// Asynchronously deliver [`Dispatch`] to the host application for
    /// processing.
    pub fn dispatch(&self, payload: Dispatch) -> Result<(), DispatchError> {
        match self.tx.try_send(payload) {
            Ok(()) => Ok(()),
            Err(TrySendError::Closed(_)) => Err(DispatchError::DispatchClosed),
            Err(TrySendError::Full(_)) => Err(DispatchError::DispatchRequestQueueFull),
        }
    }

    /// Take ownership of a stream of [`DispatchResult`] responses.
    ///
    /// Invariant: exactly one [`DispatchResult`] should be returned per
    /// [`Dispatch`].
    ///
    /// This method returns [`Some`] on the first call only.
    pub fn take_recv_stream(&mut self) -> Option<impl Stream<Item = DispatchResult> + 'static> {
        self.rx.take().map(ReceiverStream::new)
    }
}

/// A stream to consume [`Dispatch`] requests from the client library.
#[derive(Debug)]
#[pin_project]
pub struct DispatchStream {
    #[pin]
    rx: ReceiverStream<Dispatch>,
}

impl Stream for DispatchStream {
    type Item = Dispatch;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.project();
        this.rx.poll_next(cx)
    }
}

/// The response queue is closed.
#[derive(Debug, Error)]
#[error("dispatch response queue is closed")]
pub struct DispatchResponseQueueClosed {}

/// A handle to transmit [`DispatchResult`] messages back to the client library.
#[derive(Debug, Clone)]
pub struct DispatchResponder {
    tx: mpsc::Sender<DispatchResult>,
}

impl DispatchResponder {
    /// Send the [`DispatchResult`] response to the client library for a
    /// previously received [`Dispatch`] request.
    ///
    /// Invariant: exactly one [`DispatchResult`] should be returned per
    /// [`Dispatch`].
    ///
    /// # Blocks
    ///
    /// This call blocks indefinitely should the reply queue be full. In
    /// practice this should never occur if the 1-to-1 request to response
    /// invariant is maintained.
    pub fn send_response(
        &self,
        payload: DispatchResult,
    ) -> Result<(), DispatchResponseQueueClosed> {
        match self.tx.blocking_send(payload) {
            Ok(()) => Ok(()),
            Err(_) => Err(DispatchResponseQueueClosed {}),
        }
    }
}

/// Initialise a new dispatch communication triplet.
///
/// Each type has a distinct responsibility, and is typically used by a distinct
/// part of the system:
///
///  * [`DispatchPublisher`]: request from this client library to invoke the
///    dispatch callback in the FFI layer with a provided payload.
///
///  * [`DispatchStream`]: the other side of the publisher, typically held by a
///    dedicated thread in the FFI layer; streams the dispatch requests from the
///    publisher to act on.
///
///  * [`DispatchResponder`]: propagates the result of the async dispatch call
///    back to the client library, typically called indirectly by the host
///    application through an FFI function.
///
pub fn new_dispatcher_interconnect() -> (DispatchPublisher, DispatchStream, DispatchResponder) {
    // Configure the queues to be large - they consume memory proportional to
    // load (no preallocation).
    //
    // By bounding the reply queue to match the request queue (+1 for wiggle
    // room) it is guaranteed there is always a slot in the reply queue so long
    // as the 1-to-1 request / response invariant is maintained, and therefore
    // no ACKs are lost from the FFI layer.
    let (tx1, rx1) = mpsc::channel(DISPATCH_QUEUE_LEN);
    let (tx2, rx2) = mpsc::channel(DISPATCH_QUEUE_LEN + 1);

    let publisher = DispatchPublisher {
        tx: tx1,
        rx: Some(rx2),
    };

    let stream = DispatchStream {
        rx: ReceiverStream::new(rx1),
    };

    let responder = DispatchResponder { tx: tx2 };

    (publisher, stream, responder)
}
