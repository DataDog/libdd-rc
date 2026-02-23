//! The "main" of the client library.

use std::time::Duration;

use crate::ShutdownSignal;

pub(crate) const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// The "main" function for an instance of the `rc-x509-client` library.
///
/// # Graceful Shutdown
///
/// When `shutdown` is signalled, work should cease and this function should
/// complete within [`GRACEFUL_SHUTDOWN_TIMEOUT`] else they are killed at an
/// arbitrary execution point.
pub(crate) async fn entrypoint(shutdown: ShutdownSignal) {
    shutdown.wait_for_shutdown().await;
}
