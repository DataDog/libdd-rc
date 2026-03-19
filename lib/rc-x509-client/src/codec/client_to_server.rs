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

//! Codec for outgoing [`ClientToServer`] messages.

use rc_x509_proto::{
    encode,
    protocol::v1::{
        self, ClientHello,
        client_to_server::{self, Message},
    },
};

/// All possible messages originating from this client library, sent to the RC
/// delivery backend.
#[derive(Debug, PartialEq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub(crate) enum ClientToServer {
    /// An opening handshake message sent at the start of a new connection.
    ClientHello,
}

/// Serialise this [`ClientToServer`] as a protobuf payload.
impl From<&ClientToServer> for Vec<u8> {
    fn from(value: &ClientToServer) -> Self {
        // Construct the wire type for this `value`.
        let wire = match value {
            ClientToServer::ClientHello => Message::ClientHello(ClientHello::default()),
        };

        encode(&v1::ClientToServer {
            message: Some(wire),
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn prop_message_serialisation(
            a in any::<ClientToServer>(),
            b in any::<ClientToServer>(),
        ) {
            let a_out = Vec::from(&a);
            let b_out = Vec::from(&b);

            // Invariant: deterministic serialisation.
            assert_eq!(a_out, Vec::from(&a));
            assert_eq!(b_out, Vec::from(&b));

            // Invariant: if the input message variants are equal (a == b) then
            // the output message variants are equal (a_out == b_out).
            assert_eq!(
                // If the input ClientToServer instances are the same.
                a == b,
                // Then the deterministic encoding must ensure the outputs are
                // both identical.
                a_out == b_out,
            );
        }
    }
}
