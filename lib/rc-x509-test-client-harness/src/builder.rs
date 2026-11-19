use rc_x509_client::{
    AbortOnDrop, AppInfo, ShutdownSignal,
    connection::AttestationVerifier,
    entrypoint::{LibraryEntrypoint, Main},
};
use rc_x509_roots::RootCertificate;
use rc_x509_trust::trust_store::{MemoryCertCache, TrustStore};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::client::TestClient;

const CERT_CACHE_SIZE: u64 = 100;

/// Configure a [`TestClient`] and initialise it for testing.
#[derive(Debug, Default)]
pub struct TestClientBuilder {
    ca: Option<RootCertificate>,
}

impl TestClientBuilder {
    /// Construct the [`TestClient`] according to the current config of `self`.
    pub fn build(self) -> TestClient {
        let mut client = Main::new(AppInfo::new("test", "0.0.0"));

        if let Some(ca) = &self.ca {
            cfg_select! {
                debug_assertions => client = client.with_testing_verifier(
                    TrustStore::new(
                        [ca.clone(), ca.clone()],
                        MemoryCertCache::new(CERT_CACHE_SIZE),
                    )
                ),
                _ => compile_error!("enabling testing roots is only possible in debug builds"),
            };
        }

        self.do_build(client)
    }

    /// Set the root CA to use when verifying payloads.
    ///
    /// NOTE: this can only be used in "dev" builds (with `debug_assertions`
    /// enabled) else building the client will fail with a compiler error.
    pub fn with_testing_roots(mut self, roots: RootCertificate) -> Self {
        self.ca = Some(roots);
        self
    }

    fn do_build<V>(self, client: Main<V>) -> TestClient
    where
        V: AttestationVerifier + 'static,
    {
        let (signal, stop) = ShutdownSignal::new();
        let (event_tx, event_rx) = mpsc::channel(1);
        let handle = AbortOnDrop::from(tokio::spawn(
            client.entrypoint(signal, ReceiverStream::from(event_rx)),
        ));

        TestClient::new(handle, stop, event_tx)
    }
}
