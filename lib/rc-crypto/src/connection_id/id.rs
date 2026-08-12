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

use std::fmt::Display;

use crate::hash::{HashAlgo, IncrementalHashState, Sha256};
use thiserror::Error;
use tokio_util::bytes::Bytes;
use uuid::Uuid;

/// The connection ID provided by the server cannot be verified.
#[derive(Debug, Error)]
#[error("invalid connection ID from server")]
pub struct ConnectionIdInvalid;

/// A [`ConnectionId`] uniquely identifies a single connection to the Remote
/// Config backend.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct ConnectionId(Uuid);

impl ConnectionId {
    /// Construct a new [`ConnectionId`] by deriving it from the server and
    /// client nonce values.
    pub fn new(client_nonce: &[u8], server_nonce: &[u8]) -> Self {
        let mut h = Sha256::incremental();
        h.update(server_nonce);
        h.update(client_nonce);
        let hash: [u8; 32] = h.finish().into_inner();

        // Truncate the hash, keeping the first 16 bytes and discarding the
        // rest.
        let hash: [u8; 16] = hash[..16]
            .try_into()
            .expect("infallible truncation from 32 bytes");

        // Feed the first 16 bytes of the raw byte hash into a UUIDv8
        // constructor to apply the UUIDv8 bit layout described in:
        //
        //   https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-8
        //
        let uuid = Uuid::new_v8(hash);

        Self(uuid)
    }

    /// Return the raw byte value.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The unverified [`ConnectionId`], and the input parameters needed to verify
/// it was derived from the client nonce provided to the server.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct UntrustedConnectionId {
    server_nonce: Bytes,
    id: Bytes,
}

impl UntrustedConnectionId {
    /// Construct a new [`UnverifiedConnectionId`].
    pub fn new(server_nonce: Bytes, id: Bytes) -> Self {
        Self { server_nonce, id }
    }

    /// Verify this [`UntrustedConnectionId`], proving it was derived by
    /// incorporating the `client_nonce`, and therefore can be trusted.
    pub fn verify(self, client_nonce: &Bytes) -> Result<ConnectionId, ConnectionIdInvalid> {
        let derived = ConnectionId::new(client_nonce, &self.server_nonce);

        // If the client cannot reproduce the construction of the connection ID
        // using the client nonce, this connection ID cannot be trusted.
        if derived.as_bytes() != &*self.id {
            return Err(ConnectionIdInvalid);
        }

        Ok(derived)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    fn arbitrary_bytes() -> impl Strategy<Value = Bytes> {
        prop::collection::vec(any::<u8>(), 0..1028).prop_map(Bytes::from)
    }

    use super::*;

    fn id_bytes_for(server_nonce: &Bytes, client_nonce: &Bytes) -> [u8; 16] {
        *ConnectionId::new(client_nonce, server_nonce).as_bytes()
    }

    /// A test that fails if the construction of the Connection ID is changed in
    /// a way that would cause breakage.
    #[test]
    fn test_fixture() {
        let server_nonce: [u8; 16] = [42; 16];
        let client_nonce: [u8; 16] = [13; 16];

        let id = ConnectionId::new(&client_nonce, &server_nonce);
        assert_eq!(id.to_string(), "dca7b886-dd81-8a2b-b3bb-bc3fd24da50e");
    }

    proptest! {
        /// Correct construction via the UntrustedConnectionId.
        #[test]
        fn prop_construction_from_untrusted(
            client_nonce in arbitrary_bytes(),
            server_nonce in arbitrary_bytes(),
        ) {
            let expected = id_bytes_for(&server_nonce, &client_nonce);

            let untrusted = UntrustedConnectionId::new(server_nonce.clone(), Bytes::copy_from_slice(&expected));
            assert_eq!(untrusted.server_nonce, server_nonce);
            assert_eq!(&*untrusted.id, expected);

            let trusted = untrusted.verify(&client_nonce).expect("valid inputs");
            assert_eq!(*trusted.as_bytes(), expected);
        }

        /// Rejected construction of a [`ConnectionID`] due to the proposed ID
        /// not having incorporated the client nonce.
        ///
        /// This is a security critical property to ensure that dispatch
        /// messages sent to this client are explicitly tagged for this client,
        /// and not subject to cross-client reply forcing by having tricked the
        /// client into reusing an old connection ID for which signed messages
        /// have been captured.
        #[test]
        fn prop_incorrect_client_nonce(
            client_nonce in arbitrary_bytes(),
            server_nonce in arbitrary_bytes(),
            attacker_nonce in arbitrary_bytes(),
        ) {
            // If the client ID and the ID that replaces it are identical, then
            // the client ID was incorporated, and there is no attack to detect.
            //
            // This is why the client choosing a cryptographically random nonce
            // is important!
            prop_assume!(client_nonce != attacker_nonce);

            // Create an ID the client is going to receive that does not
            // incorporate the client nonce, but instead some random other
            // (attacker) data:
            let proposed_id = id_bytes_for(&server_nonce, &attacker_nonce);

            let _: ConnectionIdInvalid =
                UntrustedConnectionId::new(server_nonce, Bytes::from_owner(proposed_id))
                    .verify(&client_nonce)
                    .expect_err("incorrect client ID must fail");
        }
    }
}
