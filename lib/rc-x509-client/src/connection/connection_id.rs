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

use thiserror::Error;
use tokio_util::bytes::Bytes;

/// The connection ID provided by the server cannot be verified.
#[derive(Debug, Error)]
#[error("invalid connection ID from server")]
pub struct ConnectionIdInvalid;

/// A [`ConnectionId`] uniquely identifies a single connection to the Remote
/// Config backend.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct ConnectionId(
    #[cfg_attr(test, proptest(strategy = "crate::tests::arbitrary_bytes()"))] Bytes,
);

impl ConnectionId {
    /// Construct a new [`ConnectionId`] by deriving it from the server and
    /// client nonce values.
    pub fn new(_client_nonce: Bytes, _server_nonce: Bytes) -> Self {
        Self(Bytes::default()) // TODO(dom): implement + verify + test
    }

    /// Return the raw byte value.
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }
}

/// The unverified [`ConnectionId`], and the input parameters needed to verify
/// it was derived from the client nonce provided to the server.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct UntrustedConnectionId {
    #[cfg_attr(test, proptest(strategy = "crate::tests::arbitrary_bytes()"))]
    server_nonce: Bytes,
    #[cfg_attr(test, proptest(strategy = "crate::tests::arbitrary_bytes()"))]
    id: Bytes,
}

impl UntrustedConnectionId {
    /// Construct a new [`UnverifiedConnectionId`].
    pub fn new(server_nonce: Bytes, id: Bytes) -> Self {
        Self { server_nonce, id }
    }

    /// Verify this [`UntrustedConnectionId`], proving it was derived by
    /// incorporating the `client_nonce`, and therefore can be trusted.
    pub fn verify(self, client_nonce: Bytes) -> Result<ConnectionId, ConnectionIdInvalid> {
        let derived = ConnectionId::new(client_nonce, self.server_nonce);

        // If the client cannot reproduce the construction of the connection ID
        // using the client nonce, this connection ID cannot be trusted.
        if *derived.as_bytes() != self.id {
            return Err(ConnectionIdInvalid);
        }

        Ok(derived)
    }
}
