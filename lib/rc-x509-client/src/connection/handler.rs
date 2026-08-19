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

use futures::pin_mut;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    codec::{DecodingError, ServerToClient},
    dispatch::{DispatchPublisher, DispatchResult},
    host_runtime::Connection,
};

/// The control loop for a single connection to the RC backend.
#[derive(Debug)]
pub(crate) struct ConnectionHandler<IO> {
    /// The interface through which I/O events can be communicated via the host
    /// application.
    ///
    /// All I/O events are asynchronously delivered / received, but maintain
    /// their order.
    io: IO,

    /// Application dispatch request / response bridge.
    dispatcher: DispatchPublisher,
}

impl<IO> ConnectionHandler<IO>
where
    IO: Connection,
{
    /// Construct a new handler to own `io` and the associated `dispatcher` for
    /// that connection.
    ///
    /// [`Self::run()`] must be called to completion in order to drive the
    /// connection control loop.
    pub(crate) fn new(io: IO, dispatcher: DispatchPublisher) -> Self {
        Self { io, dispatcher }
    }

    /// Run the connection control loop to completion.
    ///
    /// Use `stop` to request a graceful shutdown of this task.
    pub(crate) async fn run(mut self, stop: CancellationToken) {
        let dispatch_ack = self.dispatcher.take_recv_stream().expect("first call");
        let server_messages = self.io.take_recv_stream().expect("first call");

        pin_mut!(dispatch_ack);
        pin_mut!(server_messages);

        loop {
            tokio::select! {
                biased; // Priority select in the order below:

                // Prefer draining the dispatch queue and completing existing
                // in-flight dispatches prior to accepting new work.

                v = dispatch_ack.next() => {
                    match v {
                        Some(v) => self.dispatch_response(v).await,
                        None => { debug!("dispatch response closed"); return }
                    }
                }
                _ = stop.cancelled() => {
                    return;
                }

                // In-flight messages from the server are dropped when the
                // connection is shut down; the host application isn't going to
                // forward any responses for this client after calling
                // connection shutdown anyway.

                v = server_messages.next() => {
                    match v {
                        Some(v) => self.server_message(v).await,
                        None => { debug!("server connection closed"); return }
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

        unimplemented!()
    }

    async fn dispatch_response(&mut self, _v: DispatchResult) {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{dispatch::new_dispatcher_interconnect, mocks::io::new_io_pair};

    use super::*;

    #[tokio::test]
    async fn test_graceful_stop_signal() {
        let (client, _server) = new_io_pair();
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();

        let actor = ConnectionHandler::new(client, dispatch_publish);

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

    #[tokio::test]
    async fn test_graceful_stop_io() {
        let (client, server) = new_io_pair();
        let (dispatch_publish, _dispatch_stream, _dispatch_responder) =
            new_dispatcher_interconnect();

        let actor = ConnectionHandler::new(client, dispatch_publish);

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

    #[tokio::test]
    async fn test_graceful_stop_dispatch_response_stream() {
        let (client, _server) = new_io_pair();
        let (dispatch_publish, _dispatch_stream, dispatch_responder) =
            new_dispatcher_interconnect();

        let actor = ConnectionHandler::new(client, dispatch_publish);

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
}
