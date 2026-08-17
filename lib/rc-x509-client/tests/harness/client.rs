use std::time::Duration;

use rc_x509_client::{
    AbortOnDrop, ShutdownCtl, ShutdownSignal,
    codec::{ClientToServer, DecodingError, ServerToClient},
    connection::{ConnectionEvent, ConnectionUpdate},
    dispatch::{DispatchResponder, DispatchStream, new_dispatcher_interconnect},
    entrypoint::{LibraryEntrypoint, Main},
};
use tokio::{sync::mpsc, time::timeout};
use tokio_stream::wrappers::ReceiverStream;

use crate::harness::io::{MockIO, MockIOServer, new_io_pair};

#[derive(Debug)]
pub(crate) struct TestClient {
    handle: AbortOnDrop<()>,
    stop: ShutdownCtl,

    event_tx: mpsc::Sender<ConnectionUpdate<MockIO>>,
}

impl TestClient {
    /// Construct a new test client.
    pub(crate) fn new() -> Self {
        let (signal, stop) = ShutdownSignal::new();

        let client = Main::default();

        let (event_tx, event_rx) = mpsc::channel(1);
        let handle = AbortOnDrop::from(tokio::spawn(
            client.entrypoint(signal, ReceiverStream::from(event_rx)),
        ));

        Self {
            handle,
            stop,

            event_tx,
        }
    }

    /// Register a new connection with the client, returning a handle to the
    /// connection.
    #[must_use]
    pub(crate) async fn new_connection(&mut self) -> TestConn {
        let (io, server) = new_io_pair();
        let (dispatch_publisher, dispatch_stream, dispatch_response) =
            new_dispatcher_interconnect();

        // Initialise the connection:
        self.event_tx
            .send(ConnectionUpdate::new(ConnectionEvent::Init))
            .await
            .expect("notify: connection init");

        // And signal it is ready for I/O to begin:
        self.event_tx
            .send(ConnectionUpdate::new(ConnectionEvent::Connected(
                io,
                dispatch_publisher,
            )))
            .await
            .expect("notify: connection connected");

        TestConn {
            io: server,
            _dispatch_stream: dispatch_stream,
            _dispatch_response: dispatch_response,
        }
    }

    /// Gracefully stop the client and wait for it to return.
    pub(crate) async fn shutdown(self) {
        self.stop.shutdown_now();

        let _: () = timeout(Duration::from_secs(5), self.handle.into_inner())
            .await
            .expect("graceful shutdown timeout")
            .expect("client panic");
    }
}

impl Default for TestClient {
    fn default() -> Self {
        Self::new()
    }
}

/// A connection to the client library.
#[derive(Debug)]
pub(crate) struct TestConn {
    io: MockIOServer,
    _dispatch_stream: DispatchStream,
    _dispatch_response: DispatchResponder,
}

impl TestConn {
    /// Push `v` to the client over the mocked transport.
    pub(crate) async fn send(&mut self, v: Result<ServerToClient, DecodingError>) {
        self.io.send(v).await.expect("failed to send to client")
    }

    /// Wait for the client to send a [`ClientToServer`].
    pub(crate) async fn recv(&mut self) -> ClientToServer {
        self.io.recv().await.expect("failed to recv from client")
    }
}
