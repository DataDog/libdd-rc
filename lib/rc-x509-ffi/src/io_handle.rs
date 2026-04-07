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

use tokio::sync::mpsc::{self, error::TrySendError};
use tokio_stream::wrappers::ReceiverStream;

use rc_x509_client::{
    codec::{ClientToServer, DecodingError, ServerToClient},
    host_runtime::{Connection, ConnectionErr},
};

/// An [`IOHandle`] provides a [`Connection`] implementation brokered through
/// the FFI host.
#[derive(Debug)]
pub struct IOHandle {
    tx: mpsc::Sender<ClientToServer>,
    rx: Option<mpsc::Receiver<Result<ServerToClient, DecodingError>>>,
}

impl IOHandle {
    pub fn new(
        tx: mpsc::Sender<ClientToServer>,
        rx: mpsc::Receiver<Result<ServerToClient, DecodingError>>,
    ) -> Self {
        Self { tx, rx: Some(rx) }
    }
}

impl Connection for IOHandle {
    async fn send(&mut self, payload: ClientToServer) -> Result<(), ConnectionErr> {
        match self.tx.try_send(payload) {
            Ok(()) => Ok(()),
            Err(TrySendError::Closed(_)) => Err(ConnectionErr::Closed),
            Err(TrySendError::Full(_)) => Err(ConnectionErr::QueueFull),
        }
    }

    type Incoming = tokio_stream::wrappers::ReceiverStream<Result<ServerToClient, DecodingError>>;

    fn take_recv_stream(&mut self) -> Option<Self::Incoming> {
        self.rx.take().map(ReceiverStream::new)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use tokio_stream::StreamExt;

    use super::*;

    #[tokio::test]
    async fn test_send_recv() {
        let (tx, mut rx_ffi_layer) = mpsc::channel(2);
        let (tx_ffi_layer, rx) = mpsc::channel(2);

        let mut handle = IOHandle::new(tx, rx);

        // Sending through the handle.
        handle.send(ClientToServer::Pong).await.unwrap();
        assert_matches!(rx_ffi_layer.recv().await, Some(ClientToServer::Pong));

        let mut rx_stream = handle.take_recv_stream().expect("must yield stream");
        assert!(handle.take_recv_stream().is_none()); // Only yielded once

        tx_ffi_layer
            .send(Err(DecodingError::NoMessage))
            .await
            .unwrap();
        assert_matches!(rx_stream.next().await, Some(Err(DecodingError::NoMessage)));
    }
}
