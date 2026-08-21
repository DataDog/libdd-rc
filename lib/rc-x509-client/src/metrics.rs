use crate::{
    build_version::BuildVersion,
    connection::{GracefulDisconnectionCount, LastConnectedDuration, UngracefulDisconnectionCount},
};

/// Metrics collected by the client library across connections.
#[derive(Debug, Default)]
pub(crate) struct InstanceMetrics {
    version: BuildVersion,

    graceful_disconnect: GracefulDisconnectionCount,
    ungraceful_disconnect: UngracefulDisconnectionCount,
    last_conn_duration: LastConnectedDuration,
}

impl InstanceMetrics {
    /// Return the [`BuildVersion`] for this execution.
    pub(crate) fn version(&self) -> &BuildVersion {
        &self.version
    }

    pub(crate) fn graceful_disconnect(&self) -> GracefulDisconnectionCount {
        self.graceful_disconnect
    }

    pub(crate) fn ungraceful_disconnect(&self) -> UngracefulDisconnectionCount {
        self.ungraceful_disconnect
    }

    pub(crate) fn last_conn_duration(&self) -> LastConnectedDuration {
        self.last_conn_duration
    }
}

// TODO: record metrics
