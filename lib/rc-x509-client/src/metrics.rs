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
