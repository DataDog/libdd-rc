// Copyright 2026 Datadog, Inc
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

//! The "main" of the client library.

use std::time::Duration;

use tracing::info;

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
    info!(
        version = env!("CARGO_PKG_VERSION"),
        "starting rc-x509-client instance"
    );

    shutdown.wait_for_shutdown().await;
}
