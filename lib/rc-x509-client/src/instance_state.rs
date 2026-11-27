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

use std::{
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use crate::{
    build_version::BuildVersion,
    connection::{
        GracefulDisconnectionCount, LastConnectedDuration, ReconnectionData,
        UngracefulDisconnectionCount,
    },
};

/// Metrics collected by the client library across connections.
#[derive(Debug, Default)]
pub(crate) struct InstanceMetrics {
    version: BuildVersion,

    graceful_disconnect: GracefulDisconnectionCount,
    ungraceful_disconnect: UngracefulDisconnectionCount,

    /// Number of seconds the last connection was connected for.
    last_conn_duration: AtomicU64,

    /// The most recent opaque [`ReconnectionData`] provided by the server, to
    /// be reflected back in the next `ClientHello`.
    reconnection_data: Mutex<Option<ReconnectionData>>,
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
        LastConnectedDuration::new(Duration::from_secs(
            self.last_conn_duration.load(Ordering::Relaxed),
        ))
    }

    pub(crate) fn set_last_conn_duration(&self, v: Duration) {
        self.last_conn_duration
            .store(v.as_secs(), Ordering::Relaxed);
    }

    /// Return the most recently set [`ReconnectionData`], if any.
    pub(crate) fn reconnection_data(&self) -> Option<ReconnectionData> {
        self.reconnection_data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone() // Refclone
    }

    /// Replace the [`ReconnectionData`] to send in subsequent handshakes.
    pub(crate) fn set_reconnection_data(&self, v: ReconnectionData) {
        *self
            .reconnection_data
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(v);
    }
}

// TODO: record disconnection metrics

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn test_version() {
        let m = InstanceMetrics::default();
        let version = BuildVersion::from_build();

        assert_eq!(*m.version(), version);
    }

    proptest! {
        /// Storing and reading back last connection duration.
        #[test]
        fn prop_last_conn_duration(
            values in prop::collection::vec(any::<Duration>(), 2..20),
        ) {
            let m = InstanceMetrics::default();

            for v in values {
                m.set_last_conn_duration(v);
                assert_eq!(m.last_conn_duration().as_seconds(), v.as_secs());
            }
        }

        /// Storing and reading back reconnection data, with the last write
        /// winning.
        #[test]
        fn prop_reconnection_data(
            values in prop::collection::vec(any::<ReconnectionData>(), 1..20),
        ) {
            let m = InstanceMetrics::default();
            assert_eq!(m.reconnection_data(), None);

            for v in values {
                m.set_reconnection_data(v.clone());
                assert_eq!(m.reconnection_data(), Some(v));
            }
        }
    }
}
