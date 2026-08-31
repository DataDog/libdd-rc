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

use std::sync::Arc;

use futures::pin_mut;
use tokio::time::Instant;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    codec::{DecodingError, ServerToClient},
    connection::handler::{ServerMessageDelegate, delegate::MessageDelegate},
    dispatch::{DispatchPublisher, DispatchResult},
    host_runtime::Connection,
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

    /// Cancelled when the connection should be gracefully shutdown due to the
    /// client stopping.
    stop: CancellationToken,

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
        stop: CancellationToken,
        dispatcher: DispatchPublisher,
        metrics: Arc<InstanceMetrics>,
    ) -> Self {
        Self {
            io,
            stop: stop.clone(),
            dispatcher,
            delegate: MessageDelegate::new(stop, Arc::clone(&metrics)),
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
    pub(crate) async fn run(self) {
        // Grab the timestamp for connection lifetime reporting later.
        let start = Instant::now();
        let metrics = Arc::clone(&self.metrics);

        // Run the main actor loop.
        self.run_loop().await;

        // Record the duration this connection was active.
        metrics.set_last_conn_duration(start.elapsed());
    }

    async fn run_loop(mut self) {
        let dispatch_ack = self.dispatcher.take_recv_stream().expect("first call");
        let server_messages = self.io.take_recv_stream().expect("first call");

        // The first action is to send the connection-opening ClientHello
        // handshake message to begin the protocol. The ClientHelloAck will be
        // handled via the delegate path below.
        self.delegate.send_hello(&mut self.io).await;

        pin_mut!(dispatch_ack);
        pin_mut!(server_messages);

        loop {
            tokio::select! {
                biased; // Priority select in the order below:

                // In-flight messages from the server and dispatch responses are
                // dropped when the connection is shut down; the host
                // application isn't going to forward any messages for this
                // client after calling for connection shutdown.
                _ = self.stop.cancelled() => {
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
        debug!(?msg, "received message from server");

        // Delegate processing of messages to the dedicated handler:
        self.delegate.process(msg, &mut self.io).await;
    }

    async fn dispatch_response(&mut self, v: DispatchResult) {
        debug!(?v, "received dispatch result from application");

        // TODO(dom): implement dispatch responses
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use assert_matches::assert_matches;

    use crate::{
        codec::ClientToServer, dispatch::new_dispatcher_interconnect, mocks::io::new_io_pair,
    };

    use super::*;

    /// The actor stops when asked.
    #[tokio::test]
    async fn test_graceful_stop_signal() {
        let (client, _server) = new_io_pair();
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();

        let stop = CancellationToken::default();
        let actor = ConnectionActor::new(
            client,
            stop.clone(),
            dispatch_publish,
            Arc::new(InstanceMetrics::default()),
        );

        let task = tokio::spawn(actor.run());

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

        let stop = CancellationToken::default();
        let actor = ConnectionActor::new(
            client,
            stop.clone(),
            dispatch_publish,
            Arc::new(InstanceMetrics::default()),
        );

        let task = tokio::spawn(actor.run());

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

        let stop = CancellationToken::default();
        let actor = ConnectionActor::new(
            client,
            stop.clone(),
            dispatch_publish,
            Arc::new(InstanceMetrics::default()),
        );

        let task = tokio::spawn(actor.run());

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

        let stop = CancellationToken::default();
        let actor = ConnectionActor::new(
            client,
            stop.clone(),
            dispatch_publish,
            Arc::new(InstanceMetrics::default()),
        );

        // Before the actor runs for the first time, stage the two inputs to
        // race:
        stop.cancel();
        server
            .send(Ok(ServerToClient::Ping))
            .await
            .expect("buffered");

        // Run the task:
        let task = tokio::spawn(actor.run());

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
}
