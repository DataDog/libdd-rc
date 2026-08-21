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

use std::{sync::Arc, time::Duration};

use futures::pin_mut;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    codec::{ClientToServer, DecodingError, ServerToClient},
    connection::handler::{
        SendToServer, ServerMessageDelegate, delegate::MessageDelegate, hello::build_hello,
    },
    dispatch::{DispatchPublisher, DispatchResult},
    host_runtime::{Connection, ConnectionErr},
    metrics::InstanceMetrics,
};

/// The control loop for a single connection to the RC backend.
#[derive(Debug)]
pub(crate) struct ConnectionActor<IO, T> {
    /// The interface through which I/O events can be communicated via the host
    /// application.
    ///
    /// All I/O events are asynchronously delivered / received, but maintain
    /// their order.
    io: IO,

    /// Application dispatch request / response bridge.
    dispatcher: DispatchPublisher,

    /// A [`ServerToClient`] message processing delegate.
    delegate: T,

    /// Client metrics shared across connections.
    metrics: Arc<InstanceMetrics>,
}

impl<IO> ConnectionActor<IO, MessageDelegate>
where
    IO: Connection,
{
    /// Construct a new handler to own `io` and the associated `dispatcher` for
    /// that connection.
    ///
    /// [`Self::run()`] must be called to completion in order to drive the
    /// connection control loop.
    pub(crate) fn new(
        io: IO,
        dispatcher: DispatchPublisher,
        metrics: Arc<InstanceMetrics>,
    ) -> Self {
        Self {
            io,
            dispatcher,
            delegate: MessageDelegate::default(),
            metrics,
        }
    }
}

#[allow(private_bounds)]
impl<IO, T> ConnectionActor<IO, T>
where
    IO: Connection,
    T: ServerMessageDelegate<IO>,
{
    /// Run the connection control loop to completion.
    ///
    /// Use `stop` to request a graceful shutdown of this task.
    pub(crate) async fn run(mut self, stop: CancellationToken) {
        let dispatch_ack = self.dispatcher.take_recv_stream().expect("first call");
        let server_messages = self.io.take_recv_stream().expect("first call");

        // The first action is to send the connection-opening ClientHello
        // handshake message to begin the protocol. The ClientHelloAck will be
        // handled via the delegate path below.
        {
            // TODO(dom): proper app name.
            let hello = build_hello("test", &self.metrics);
            retry_send(&mut self.io, hello, &stop).await
        }

        pin_mut!(dispatch_ack);
        pin_mut!(server_messages);

        loop {
            tokio::select! {
                biased; // Priority select in the order below:

                // In-flight messages from the server and dispatch responses are
                // dropped when the connection is shut down; the host
                // application isn't going to forward any messages for this
                // client after calling for connection shutdown.
                _ = stop.cancelled() => {
                    return;
                }

                // Prefer draining the dispatch queue and completing existing
                // in-flight dispatches prior to accepting new work.
                v = dispatch_ack.next() => {
                    match v {
                        Some(v) => self.dispatch_response(v).await,
                        None => { debug!("dispatch processor stopped"); return }
                    }
                }

                v = server_messages.next() => {
                    match v {
                        Some(v) => self.server_message(v).await,
                        None => { debug!("io broker stopped"); return }
                    }
                }
            };
        }
    }

    async fn server_message(&mut self, msg: Result<ServerToClient, DecodingError>) {
        let msg = match msg {
            Ok(v) => v,
            Err(e) => {
                warn!(error=%e, "dropping invalid message from server");
                return;
            }
        };

        debug!(?msg, "received message from server");

        // Delegate processing of messages to the dedicated handler:
        self.delegate.process(msg, &mut self.io).await;
    }

    async fn dispatch_response(&mut self, _v: DispatchResult) {
        unimplemented!()
    }
}

/// Retry sending `value` over `io` until it succeeds, or `stop` is cancelled.
pub(super) async fn retry_send<IO>(io: &mut IO, value: ClientToServer, stop: &CancellationToken)
where
    IO: SendToServer,
{
    loop {
        match io.send(value.clone()).await {
            Ok(_) => {
                debug!("message sent");
                break;
            }
            Err(ConnectionErr::Closed) => {
                debug!("connection closed - aborting message send");
                return;
            }
            Err(e) => warn!(error=%e, "failed to send message to server"),
        }

        tokio::select! {
            biased;

            _ = stop.cancelled() => {
                debug!("send aborted - connection closing");
                return;
            }

            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use assert_matches::assert_matches;

    use crate::{dispatch::new_dispatcher_interconnect, mocks::io::new_io_pair};

    use super::*;

    /// The actor stops when asked.
    #[tokio::test]
    async fn test_graceful_stop_signal() {
        let (client, _server) = new_io_pair();
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();

        let actor = ConnectionActor::new(client, dispatch_publish, Default::default());

        let stop = CancellationToken::default();
        let task = tokio::spawn(actor.run(stop.clone()));

        // Signal shutdown.
        stop.cancel();

        // Wait for the actor to stop:
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("timeout waiting for shutdown")
            .expect("connection control panic");
    }

    /// The actor stops when the IO broker drops the IO handle, signalling it
    /// will no longer be processing I/O requests.
    #[tokio::test]
    async fn test_graceful_stop_io() {
        let (client, server) = new_io_pair();
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();

        let actor = ConnectionActor::new(client, dispatch_publish, Default::default());

        let stop = CancellationToken::default();
        let task = tokio::spawn(actor.run(stop.clone()));

        // Drop the IO transport:
        drop(server);

        // Wait for the actor to stop:
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("timeout waiting for shutdown")
            .expect("connection control panic");
    }

    /// The actor stops when the dispatch processor signals it will no longer
    /// process dispatch requests.
    #[tokio::test]
    async fn test_graceful_stop_dispatch_response_stream() {
        let (client, _server) = new_io_pair();
        let (dispatch_publish, _dispatch_stream, dispatch_responder) =
            new_dispatcher_interconnect();

        let actor = ConnectionActor::new(client, dispatch_publish, Default::default());

        let stop = CancellationToken::default();
        let task = tokio::spawn(actor.run(stop.clone()));

        // Drop the dispatch responder, which closes the dispatch result stream:
        drop(dispatch_responder);

        // Wait for the actor to stop:
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("timeout waiting for shutdown")
            .expect("connection control panic");
    }

    // Race a graceful shutdown signal with a server message, to ensure the
    // shutdown takes priority.
    #[tokio::test]
    async fn test_race_shutdown_with_server_message() {
        let (client, mut server) = new_io_pair();
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();

        let actor = ConnectionActor::new(client, dispatch_publish, Default::default());

        let stop = CancellationToken::default();

        // Before the actor runs for the first time, stage the two inputs to
        // race:
        stop.cancel();
        server
            .send(Ok(ServerToClient::Ping))
            .await
            .expect("buffered");

        // Run the task:
        let task = tokio::spawn(actor.run(stop.clone()));

        // Wait for the actor to stop:
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("timeout waiting for shutdown")
            .expect("connection control panic");

        // The client should not have generated any PONG response, as it shut
        // down immediately (it may send a HELLO first, respecting the
        // protocol).
        assert_matches!(
            server.recv().await,
            None | Some(ClientToServer::ClientHello { .. })
        );
        assert_eq!(server.recv().await, None);
    }

    /// A successful send does not retry.
    #[tokio::test]
    async fn test_retry_send_success() {
        let (mut client, mut server) = new_io_pair();
        let stop = CancellationToken::default();

        retry_send(&mut client, ClientToServer::Pong, &stop).await;

        assert_eq!(server.recv().await, Some(ClientToServer::Pong));
    }

    /// A [`ConnectionErr::Closed`] error aborts the send immediately, without
    /// retrying.
    #[tokio::test]
    async fn test_retry_send_aborts_on_closed_connection() {
        let (mut client, server) = new_io_pair();
        let stop = CancellationToken::default();

        // Close the transport by dropping the server-side handle.
        drop(server);

        // Does not hang despite the stop token never being cancelled - the
        // closed connection is terminal.
        tokio::time::timeout(
            Duration::from_secs(5),
            retry_send(&mut client, ClientToServer::Pong, &stop),
        )
        .await
        .expect("timeout");
    }

    /// A send that keeps failing is retried, backing off between attempts,
    /// until the stop signal is observed.
    #[tokio::test(start_paused = true)]
    async fn test_retry_send_retries_until_stopped() {
        let (mut client, _server) = new_io_pair();
        let stop = CancellationToken::default();

        // Fill the bounded channel so that all sends fail with
        // ConnectionErr::QueueFull, forcing retries.
        while SendToServer::send(&mut client, ClientToServer::Pong)
            .await
            .is_ok()
        {}

        let task_stop = stop.clone();
        let task = tokio::spawn(async move {
            retry_send(&mut client, ClientToServer::Pong, &task_stop).await;
        });

        // Allow a handful of retry attempts to elapse - the queue remains
        // full throughout, so none of them should succeed and the task
        // should not have completed.
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert!(!task.is_finished());

        // Request a shutdown - the in-flight retry loop should observe it
        // and return, even though the send is still failing.
        stop.cancel();

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("timeout")
            .expect("retry_send task panicked");
    }
}
