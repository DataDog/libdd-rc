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

//! Codec for incoming [`ServerToClient`] messages.

use rc_x509_proto::{
    decode,
    protocol::v1::{self, server_to_client::Message},
};
use thiserror::Error;

/// Errors parsing incoming messages from the RC delivery backend.
#[derive(Debug, Error)]
pub(crate) enum EncodingError {
    /// The message on the wire cannot be deserialised into a message due to
    /// invalid encoding.
    #[error("deserialisation error: {0}")]
    Wire(#[from] rc_x509_proto::DecodeError),

    /// The payload cannot be decoded into a message this client understands.
    ///
    /// This may indicate an API version incompatibility (e.g. an old client is
    /// unaware of a newer message type).
    #[error("no message")]
    NoMessage,
}

/// All possible messages originating from the RC delivery backend, to an RC
/// client.
#[derive(Debug, PartialEq)]
pub(crate) enum ServerToClient {
    Placeholder,
}

/// Try to parse a protobuf encoded payload into a [`ServerToClient`].
impl TryFrom<&[u8]> for ServerToClient {
    type Error = EncodingError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let got: v1::ServerToClient = decode::<_>(value)?;

        // Construct the application type from this wire type.
        Ok(match got.message.ok_or(EncodingError::NoMessage)? {
            Message::Dummy(_) => Self::Placeholder,
        })
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use proptest::prelude::*;

    use super::*;

    /// Encode and then decode `v`, returning the result.
    fn round_trip(v: &v1::ServerToClient) -> Result<ServerToClient, EncodingError> {
        ServerToClient::try_from(rc_x509_proto::encode(v).as_slice())
    }

    #[test]
    fn test_bad_wire_encoding() {
        let got = ServerToClient::try_from([42].as_slice());
        assert_matches!(got, Err(EncodingError::Wire(_)));
    }

    #[test]
    fn test_no_message() {
        let got = round_trip(&v1::ServerToClient { message: None });
        assert_matches!(got, Err(EncodingError::NoMessage));
    }

    /// Generate a [`ServerToClient`] messages that should successfully encode &
    /// decode (always including an inner message).
    fn arbitrary_server_to_client() -> impl Strategy<Value = v1::ServerToClient> {
        any::<v1::server_to_client::Message>().prop_map(|v| v1::ServerToClient { message: Some(v) })
    }

    proptest! {
        #[test]
        fn prop_valid_message_deserialisation(
            a in arbitrary_server_to_client(),
            b in arbitrary_server_to_client(),
        ) {
            let a_out = round_trip(&a).unwrap();
            let b_out = round_trip(&b).unwrap();

            // Invariant: deterministic serialisation.
            assert_eq!(a_out, round_trip(&a).unwrap());
            assert_eq!(b_out, round_trip(&b).unwrap());

            // Invariant: if the input messages are equal (a == b) then the
            // output message variants are equal (a_out == b_out). If the input
            // message are different (a != b) then the output messages are
            // different (a_out != b_out).
            //
            // This ensures deterministic mapping of wire type -> deserialised
            // type, and that different input variants produce different output
            // variants.
            let a_msg = a.message.unwrap();
            let b_msg = b.message.unwrap();
            assert_eq!(
                // If the input enums are the same enum variants
                a_msg == b_msg,
                // Then the output enums must be the same enum variants
                a_out == b_out,
            );
        }
    }
}
