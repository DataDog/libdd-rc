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

use std::time::Duration;

use tokio::{sync::mpsc, time::timeout};
use tokio_stream::wrappers::ReceiverStream;

use crate::{
    codec::{ClientToServer, DecodingError, ServerToClient},
    host_runtime::{Connection, ConnectionErr},
};

/// A mock [`Connection`] implementation for the client library to use.
#[derive(Debug)]
pub(crate) struct MockIO {
    from_server: Option<ReceiverStream<Result<ServerToClient, DecodingError>>>,
    to_server: mpsc::Sender<ClientToServer>,
}

impl Connection for MockIO {
    type Incoming = ReceiverStream<Result<ServerToClient, DecodingError>>;

    async fn send(&mut self, payload: ClientToServer) -> Result<(), ConnectionErr> {
        match self.to_server.try_send(payload) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(ConnectionErr::Closed),
            Err(mpsc::error::TrySendError::Full(_)) => Err(ConnectionErr::QueueFull),
        }
    }

    fn take_recv_stream(&mut self) -> Option<Self::Incoming> {
        self.from_server.take()
    }
}

/// A handle to transmit messages "from the server" over the mocked transport,
/// to the client library.
pub(crate) struct MockIOServer {
    to_client: mpsc::Sender<Result<ServerToClient, DecodingError>>,
    to_server: mpsc::Receiver<ClientToServer>,
}

impl MockIOServer {
    pub(crate) fn is_connection_closed(&self) -> bool {
        self.to_client.is_closed() || self.to_server.is_closed()
    }

    pub(crate) async fn recv(&mut self) -> Option<ClientToServer> {
        timeout(Duration::from_secs(5), self.to_server.recv())
            .await
            .expect("mock transport timeout: recv from client")
    }

    pub(crate) async fn send(
        &mut self,
        v: Result<ServerToClient, DecodingError>,
    ) -> Result<(), ConnectionErr> {
        timeout(Duration::from_secs(5), self.to_client.send(v))
            .await
            .expect("mock transport timeout: sending to client")
            .map_err(|_| ConnectionErr::Closed)
    }
}

/// Construct a new IO pair that provides a mocked [`Connection`].
///
/// The client library uses the [`MockIO`] as the [`Connection`] impl, while the
/// test code retains the [`MockIOServer`] to "send" messages from the delivery
/// backend over the mocked transport.
pub(crate) fn new_io_pair() -> (MockIO, MockIOServer) {
    let (tx1, rx1) = mpsc::channel(10);
    let (tx2, rx2) = mpsc::channel(10);

    let a = MockIO {
        from_server: Some(ReceiverStream::from(rx1)),
        to_server: tx2,
    };

    let b = MockIOServer {
        to_client: tx1,
        to_server: rx2,
    };

    (a, b)
}
