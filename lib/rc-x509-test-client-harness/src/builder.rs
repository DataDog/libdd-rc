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
