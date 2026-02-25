use tokio::sync::mpsc;

use crate::host_runtime::{Connection, ConnectionErr};

/// An [`IOHandle`] provides a [`Connection`] implementation brokered through
/// the FFI host.
#[derive(Debug)]
pub(crate) struct IOHandle {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl IOHandle {
    pub(crate) fn new(tx: mpsc::Sender<Vec<u8>>, rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self { tx, rx }
    }
}

impl Connection for IOHandle {
    async fn send(&mut self, payload: Vec<u8>) -> Result<(), ConnectionErr> {
        self.tx
            .send(payload)
            .await
            .map_err(|_| ConnectionErr::Closed)
    }

    async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_send_recv() {
        let (mut tx, mut rx_ffi_layer) = mpsc::channel(2);
        let (mut tx_ffi_layer, rx) = mpsc::channel(2);

        let mut handle = IOHandle::new(tx, rx);

        // Sending through the handle.
        handle.send(vec![42]).await.unwrap();
        assert_eq!(
            rx_ffi_layer.recv().await.as_deref(),
            Some([42_u8].as_slice())
        );

        tx_ffi_layer.send(vec![13]).await.unwrap();
        assert_eq!(handle.recv().await.as_deref(), Some([13_u8].as_slice()));
    }
}
