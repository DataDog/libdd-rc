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

use std::time::Duration;

use tokio_util::bytes::Bytes;

/// A [`GracefulDisconnectionCount`] tracks the number of times a single
/// [`ConnectionId`] has been gracefully disconnected by the server. (calls to
/// `rc_conn_disconnected()`, caused by a "go away" message from the server).
///
/// Invariant: guaranteed to be sequential, starting from 0 for the first,
/// tracked per connection.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct GracefulDisconnectionCount(u64);

impl GracefulDisconnectionCount {
    /// Construct a new [`ReconnectionCount`] over the counter value.
    pub fn new(v: u64) -> Self {
        Self(v)
    }

    /// Return the raw reconnection count.
    pub fn as_raw(&self) -> u64 {
        self.0
    }
}

/// A [`UngracefulDisconnectionCount`] tracks the number of times a single
/// [`ConnectionId`] has been ungracefully forced to disconnect by a network
/// failure or other unintended event (calls to `rc_conn_disconnected()`, NOT
/// caused by a "go away" message from the server).
///
/// Invariant: guaranteed to be sequential, starting from 0 for the first,
/// tracked per connection.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct UngracefulDisconnectionCount(u64);

impl UngracefulDisconnectionCount {
    /// Construct a new [`ReconnectionCount`] over the counter value.
    pub fn new(v: u64) -> Self {
        Self(v)
    }

    /// Return the raw reconnection count.
    pub fn as_raw(&self) -> u64 {
        self.0
    }
}

/// The duration of time a connection remained open / connected to the RC
/// delivery backend before it was marked as closed by the host application.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct LastConnectedDuration(u64);

impl LastConnectedDuration {
    /// Construct a new [`LastConnectedDuration`].
    pub fn new(v: Duration) -> Self {
        Self(v.as_secs())
    }

    /// Return the number of seconds the connection was in the "open" state.
    pub fn as_seconds(&self) -> u64 {
        self.0
    }
}

/// Immutable opaque data sent by the server, to be reflected back in any
/// subsequent reconnection handshake.
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ReconnectionData(
    #[cfg_attr(test, proptest(strategy = "crate::tests::arbitrary_bytes(0..1028)"))] Bytes,
);

impl ReconnectionData {
    pub(crate) fn new(bytes: Bytes) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &Bytes {
        &self.0
    }
}
