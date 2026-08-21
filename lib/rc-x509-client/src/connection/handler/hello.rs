use rc_crypto::connection_id::IdNonce;
use tokio_util::bytes::Bytes;

use crate::{codec::ClientToServer, metrics::InstanceMetrics};

pub(super) fn build_hello(app_name: &str, metrics: &InstanceMetrics) -> ClientToServer {
    let nonce = IdNonce::default();

    ClientToServer::ClientHello {
        client_nonce: Bytes::copy_from_slice(nonce.as_bytes()),
        graceful: metrics.graceful_disconnect(),
        ungraceful: metrics.ungraceful_disconnect(),
        last_closed_connection_duration: metrics.last_conn_duration(),
        reconnection_data: None,
        version_info: metrics.version().clone(),
        app_name: app_name.to_string(),
    }
}
