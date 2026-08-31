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

use rc_crypto::connection_id::IdNonce;
use tokio_util::bytes::Bytes;

use crate::{codec::ClientToServer, metrics::InstanceMetrics};

pub(super) fn build_hello(app_name: &str, metrics: &InstanceMetrics) -> (IdNonce, ClientToServer) {
    let nonce = IdNonce::default();
    let client_nonce = Bytes::copy_from_slice(nonce.as_bytes());

    (
        nonce,
        ClientToServer::ClientHello {
            client_nonce,
            graceful: metrics.graceful_disconnect(),
            ungraceful: metrics.ungraceful_disconnect(),
            last_closed_connection_duration: metrics.last_conn_duration(),
            reconnection_data: None,
            version_info: metrics.version().clone(),
            app_name: app_name.to_string(),
        },
    )
}
