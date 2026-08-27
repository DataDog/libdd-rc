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
use tokio_util::bytes::Bytes;
use tracing::warn;

use crate::host_runtime::CorrelationId;

/// The maximum number of dispatch payloads that can be queued in memory,
/// waiting for the [`DispatchStream`] to consume.
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

    /// The attestation-verified, encoded [`v1::DispatchRequestPayload`].
    pub payload: Bytes,
}

/// The result of processing a [`Dispatch`].
///
/// Exactly one [`DispatchResult`] should be returned for each [`Dispatch`].
#[derive(Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
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
#[derive(Debug, Error, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
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
    /// dispatch thread has exited. This is a fatal state, but may be triggered
    /// by a shutdown of the client.
    #[error("dispatch task is not running")]
    DispatchClosed,

    /// An error deserialising the response from the host application.
    #[error("deserialisation error processing dispatch result from FFI host: {0}")]
    ReplyDeserialisation(
        #[cfg_attr(test, proptest(strategy = "tests::arbitrary_decode_error()"))] DecodeError,
    ),

    /// Catch-all if the FFI layer returns an unknown error code.
    ///
    /// The FFI layer / host application is required to return a serialised
    /// [`v1::DispatchResponsePayload`] as a dispatch response, but the data
    /// they provided could not be deserialised.
    #[error("unknown dispatch error from host app")]
    UnknownHostDispatchError,
}

impl From<DispatchError> for v1::dispatch_response::DispatchError {
    fn from(value: DispatchError) -> Self {
        match value {
            DispatchError::UnknownPayload => Self::UnknownPayload,
            DispatchError::NoDispatchHandler => Self::NoDispatchHandler,
            DispatchError::HandlerQueueFull => Self::HandlerQueueFull,
            DispatchError::DispatchRequestQueueFull => Self::DispatchQueueFull,
            DispatchError::DispatchClosed => Self::Closed,
            DispatchError::ReplyDeserialisation(_) => Self::ReplyDeserialisation,
            DispatchError::UnknownHostDispatchError => Self::ClientReturnedUnknown,
        }
    }
}

/// A handle to publish [`Dispatch`] requests to the host application and
/// receive [`DispatchResult`] responses.
#[derive(Debug)]
pub struct DispatchPublisher {
    tx: mpsc::Sender<Dispatch>,
    rx: Option<mpsc::Receiver<DispatchResult>>,

    /// A weak handle used to self-report [`DispatchError`] onto the response
    /// stream.
    ///
    /// This MUST be weak, not a [`DispatchResponder`] (strong reference) -
    /// otherwise this [`DispatchPublisher`] will keep the response channel
    /// open, preventing the connection actor from ever observing the channel
    /// close when the host application drops its [`DispatchResponder`] to
    /// signal it has stopped processing dispatches.
    errors: mpsc::WeakSender<DispatchResult>,
}

impl DispatchPublisher {
    /// Asynchronously deliver [`Dispatch`] to the host application for
    /// processing.
    ///
    /// ## Errors
    ///
    /// If an error is returned, a relevant [`DispatchError`] is published to
    /// the response stream (if still live), a warn log is emitted and the
    /// request is dropped.
    ///
    /// ## Blocking
    ///
    /// This method is wait-free in the happy path, but blocks to push an error
    /// if the dispatch queue experiences an error.
    pub async fn dispatch(&self, payload: Dispatch) -> Result<(), DispatchError> {
        let correlation_id = payload.correlation_id;

        let err = match self.tx.try_send(payload) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Closed(_)) => DispatchError::DispatchClosed,
            Err(TrySendError::Full(_)) => DispatchError::DispatchRequestQueueFull,
        };

        warn!(%correlation_id, error=%err, "dispatch failure");

        if let Some(tx) = self.errors.upgrade() {
            let _ = tx
                .send(DispatchResult {
                    correlation_id,
                    result: Err(err.clone()),
                })
                .await;
        }

        Err(err)
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
    pub async fn send_response(
        &self,
        payload: DispatchResult,
    ) -> Result<(), DispatchResponseQueueClosed> {
        match self.tx.send(payload).await {
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

    let errors = tx2.downgrade();
    let responder = DispatchResponder { tx: tx2 };

    let publisher = DispatchPublisher {
        tx: tx1,
        rx: Some(rx2),
        errors,
    };

    let stream = DispatchStream {
        rx: ReceiverStream::new(rx1),
    };

    (publisher, stream, responder)
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use futures::StreamExt;
    use proptest::prelude::*;

    use super::*;
    use crate::host_runtime::CorrelationId;

    /// Generate a static but arbitrary protobuf deserialisation error.
    pub(super) fn arbitrary_decode_error() -> impl Strategy<Value = DecodeError> {
        // Deserialise some nonsense to generate a prost error:
        Just(rc_x509_proto::decode::<v1::Pong>(&[42][..]).expect_err("malformed input"))
    }

    /// A successfully queued [`Dispatch`] request is delivered to the
    /// [`DispatchStream`] consumer.
    #[tokio::test]
    async fn test_dispatch_delivered_to_stream() {
        let (publisher, mut stream, _responder) = new_dispatcher_interconnect();

        let correlation_id = CorrelationId::new(42);
        publisher
            .dispatch(Dispatch {
                correlation_id,
                payload: Bytes::from_static(&[1, 2, 3]),
            })
            .await
            .expect("queue has capacity");

        let got = stream.next().await.expect("must have queued request");
        assert_eq!(got.correlation_id, correlation_id);
        assert_eq!(got.payload, Bytes::from_static(&[1, 2, 3]));
    }

    /// [`DispatchPublisher::take_recv_stream`] only yields the stream on the
    /// first call.
    #[test]
    fn test_take_recv_stream_once() {
        let (mut publisher, _stream, _responder) = new_dispatcher_interconnect();

        assert!(publisher.take_recv_stream().is_some());
        assert!(publisher.take_recv_stream().is_none());
    }

    /// A [`DispatchResult`] sent via the [`DispatchResponder`] is observed on
    /// the stream returned by [`DispatchPublisher::take_recv_stream`].
    #[tokio::test]
    async fn test_responder_delivers_to_recv_stream() {
        let (mut publisher, _stream, responder) = new_dispatcher_interconnect();
        let mut recv = publisher.take_recv_stream().expect("first call");

        let correlation_id = CorrelationId::new(7);

        responder
            .send_response(DispatchResult {
                correlation_id,
                result: Err(DispatchError::UnknownPayload),
            })
            .await
            .expect("queue has capacity");

        let got = recv.next().await.expect("must have queued response");
        assert_eq!(got.correlation_id, correlation_id);
        assert_matches!(got.result, Err(DispatchError::UnknownPayload));
    }

    /// [`DispatchResponder::send_response`] fails once the client library has
    /// dropped the response stream.
    #[tokio::test]
    async fn test_send_response_after_recv_dropped() {
        let (mut publisher, _stream, responder) = new_dispatcher_interconnect();

        // Take, then drop, the receive stream - closing the response queue.
        drop(publisher.take_recv_stream().expect("first call"));

        let got = responder
            .send_response(DispatchResult {
                correlation_id: CorrelationId::new(1),
                result: Err(DispatchError::UnknownPayload),
            })
            .await;

        assert_matches!(got, Err(DispatchResponseQueueClosed {}));
    }

    /// When the [`DispatchStream`] consumer has been dropped, further
    /// [`DispatchPublisher::dispatch`] calls fail immediately, and the same
    /// error is self-reported on the response stream so that a caller
    /// awaiting the [`DispatchResult`] observes the failure too.
    #[tokio::test]
    async fn test_dispatch_after_stream_dropped_self_reports_error() {
        let (mut publisher, stream, _responder) = new_dispatcher_interconnect();
        let mut recv = publisher.take_recv_stream().expect("first call");

        // Close the request queue by dropping the consumer side.
        drop(stream);

        let correlation_id = CorrelationId::new(99);
        let err = publisher
            .dispatch(Dispatch {
                correlation_id,
                payload: Bytes::from_static(&[9]),
            })
            .await
            .expect_err("request queue closed");
        assert_matches!(err, DispatchError::DispatchClosed);

        let got = recv.next().await.expect("must have self-reported error");
        assert_eq!(got.correlation_id, correlation_id);
        assert_matches!(got.result, Err(DispatchError::DispatchClosed));
    }

    /// A full request queue causes [`DispatchPublisher::dispatch`] to fail
    /// with [`DispatchError::DispatchRequestQueueFull`], which is also
    /// self-reported on the response stream.
    #[tokio::test]
    async fn test_dispatch_queue_full_self_reports_error() {
        let (mut publisher, _stream, _responder) = new_dispatcher_interconnect();
        let mut recv = publisher.take_recv_stream().expect("first call");

        // Fill the bounded request queue without draining `_stream`, so the
        // next dispatch() call observes a full queue.
        for i in 0..DISPATCH_QUEUE_LEN {
            publisher
                .dispatch(Dispatch {
                    correlation_id: CorrelationId::new(i as u64),
                    payload: Bytes::new(),
                })
                .await
                .expect("queue has capacity");
        }

        let correlation_id = CorrelationId::new(u64::MAX);
        let err = publisher
            .dispatch(Dispatch {
                correlation_id,
                payload: Bytes::new(),
            })
            .await
            .expect_err("queue is full");
        assert_matches!(err, DispatchError::DispatchRequestQueueFull);

        let got = recv.next().await.expect("must have self-reported error");
        assert_eq!(got.correlation_id, correlation_id);
        assert_matches!(got.result, Err(DispatchError::DispatchRequestQueueFull));
    }

    proptest! {
        /// Distinct [`DispatchError`] variants must encode to distinct
        /// [`v1::dispatch_response::DispatchError`] wire values, otherwise the
        /// backend cannot distinguish between the failure modes reported.
        #[test]
        fn prop_dispatch_error_encoding_is_injective(
            a in any::<DispatchError>(),
            b in any::<DispatchError>(),
        ) {
            let encoded_a = v1::dispatch_response::DispatchError::from(a.clone());
            let encoded_b = v1::dispatch_response::DispatchError::from(b.clone());

            if std::mem::discriminant(&a) != std::mem::discriminant(&b) {
                prop_assert_ne!(encoded_a, encoded_b);
            } else {
                prop_assert_eq!(encoded_a, encoded_b);
            }
        }
    }
}
