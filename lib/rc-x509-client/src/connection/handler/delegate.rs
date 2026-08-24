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

use std::{fmt::Debug, sync::Arc, time::Duration};

use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    codec::{ClientToServer, ServerToClient},
    connection::handler::{SendToServer, ServerMessageDelegate, hello::build_hello},
    host_runtime::ConnectionErr,
    metrics::InstanceMetrics,
};

/// Handler for [`ServerToClient`] messages (an implementation of
/// [`ServerMessageDelegate`]).
#[derive(Debug)]
pub(crate) struct MessageDelegate {
    metrics: Arc<InstanceMetrics>,
    stop: CancellationToken,
}

impl MessageDelegate {
    pub(crate) fn new(stop: CancellationToken, metrics: Arc<InstanceMetrics>) -> Self {
        Self { metrics, stop }
    }
}

impl<IO> ServerMessageDelegate<IO> for MessageDelegate
where
    IO: SendToServer,
{
    async fn process(&mut self, msg: ServerToClient, reply: &mut IO) {
        match msg {
            ServerToClient::Ping => reply.send(ClientToServer::Pong).await.expect("pong!"),
            ServerToClient::ClientHelloAck { connection_id } => {
                debug!(?connection_id, "obtained unverified connection ID");
            }
            _ => unimplemented!(),
        }
    }

    async fn send_hello(&mut self, reply: &mut IO) {
        let hello = build_hello("test", &self.metrics);
        retry_send(reply, hello, &self.stop).await
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
    use assert_matches::assert_matches;

    use crate::mocks::io::new_io_pair;

    use super::*;

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

    /// Test handling of a PING server message.
    #[tokio::test]
    async fn test_ping_pong() {
        let mut d = MessageDelegate::new(CancellationToken::default(), Arc::new(InstanceMetrics::default()));

        let (mut client, mut server) = new_io_pair();

        d.process(ServerToClient::Ping, &mut client).await;

        let got = server.recv().await.expect("must reply");
        assert_matches!(got, ClientToServer::Pong);
    }
}
