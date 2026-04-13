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

use rc_crypto::certificate::InvalidDer;
use rc_x509_proto::{
    decode,
    protocol::v1::{self, server_to_client::Message},
};
use thiserror::Error;

use crate::trust::UntrustedCert;

/// Errors parsing incoming messages from the RC delivery backend.
#[derive(Debug, Error)]
pub enum DecodingError {
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

    /// A certificate was sent by the server that couldn't be parsed.
    #[error("invalid certificate DER bytes: {0}")]
    InvalidCert(#[from] InvalidDer),
}

/// All possible messages originating from the RC delivery backend, to an RC
/// client.
#[derive(Debug, PartialEq)]
pub enum ServerToClient {
    /// The server has requested an immediate PONG response.
    Ping,

    /// The server has pushed a new (untrusted) X509 certificate to the client.
    ///
    /// This certificate MUST be treated as untrusted input.
    CertificatePush(UntrustedCert),
}

/// Try to parse a protobuf encoded payload into a [`ServerToClient`].
impl TryFrom<&[u8]> for ServerToClient {
    type Error = DecodingError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let got: v1::ServerToClient = decode::<_>(value)?;

        // Construct the application type from this wire type.
        Ok(match got.message.ok_or(DecodingError::NoMessage)? {
            Message::Ping(_) => Self::Ping,
            Message::CertificatePush(cert) => {
                Self::CertificatePush(UntrustedCert::from_der(cert.der)?)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use proptest::prelude::*;
    use rc_crypto::certificate::Certificate;

    use super::*;

    /// Certificate:
    ///     Data:
    ///         Version: 3 (0x2)
    ///         Serial Number:
    ///             e2:7b:94:b7:3c:3d:08:ba:df:45:8d:56:7a:a5:e1:64
    ///         Signature Algorithm: ecdsa-with-SHA256
    ///         Issuer: O=La Fábrica de Plátanos, CN=La Fábrica de Plátanos Intermediate CA
    ///         Validity
    ///             Not Before: Aug 13 14:58:40 2025 GMT
    ///             Not After : Aug 11 14:59:40 2035 GMT
    ///         Subject: CN=itsallbroken.com
    ///         Subject Public Key Info:
    ///             Public Key Algorithm: id-ecPublicKey
    ///                 Public-Key: (256 bit)
    ///                 pub:
    ///                     04:41:cb:25:c3:11:f4:fc:7f:39:f0:bd:91:71:42:
    ///                     3a:ac:65:3d:ee:19:b1:06:bd:c1:6d:d5:f2:63:30:
    ///                     c7:3c:1d:0c:2b:c7:ec:f5:9f:5b:eb:8a:a1:fe:cb:
    ///                     3f:0f:57:67:a1:75:7e:64:d3:c3:56:31:1b:53:59:
    ///                     e7:a1:8f:a5:41
    ///                 ASN1 OID: prime256v1
    ///                 NIST CURVE: P-256
    ///         X509v3 extensions:
    ///             X509v3 Key Usage: critical
    ///                 Digital Signature
    ///             X509v3 Extended Key Usage:
    ///                 TLS Web Server Authentication, TLS Web Client Authentication
    ///             X509v3 Subject Key Identifier:
    ///                 DC:8D:B6:27:52:78:58:4C:FD:A2:43:DB:CB:2B:E0:57:68:6E:2B:8E
    ///             X509v3 Authority Key Identifier:
    ///                 20:6C:8E:CF:E4:21:A7:FF:ED:23:C8:3D:37:0F:77:81:84:71:0E:15
    ///             X509v3 Subject Alternative Name:
    ///                 DNS:itsallbroken.com
    ///             1.3.6.1.4.1.37476.9000.64.1:
    ///                 0F.....dom@itsallbroken.com.+lhMX56UQUB5e2soGXs7dQpNp_-co_AS7tvJhBk-hqIk
    ///     Signature Algorithm: ecdsa-with-SHA256
    ///     Signature Value:
    ///         30:45:02:20:0d:42:b0:ad:58:8d:1e:8c:58:72:c9:d7:29:b2:
    ///         ba:90:e6:f4:a5:2f:6e:8f:21:60:63:ba:b1:2c:17:b8:bd:27:
    ///         02:21:00:c4:d7:63:16:75:1c:f1:81:67:8d:e6:60:46:84:74:
    ///         c4:78:ed:89:50:94:dc:30:2b:ee:37:c9:30:c1:46:07:7b
    /// sha256 Fingerprint=49:EF:BB:E5:7F:3D:FF:9C:6D:B5:6A:15:B7:24:BA:8B:78:76:9C:16:A6:58:75:F9:B7:76:AE:EE:21:53:E5:E5
    const SAMPLE_CERT_DER: &[u8] = &[
        48, 130, 2, 90, 48, 130, 2, 0, 160, 3, 2, 1, 2, 2, 17, 0, 226, 123, 148, 183, 60, 61, 8,
        186, 223, 69, 141, 86, 122, 165, 225, 100, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48,
        86, 49, 33, 48, 31, 6, 3, 85, 4, 10, 12, 24, 76, 97, 32, 70, 195, 161, 98, 114, 105, 99,
        97, 32, 100, 101, 32, 80, 108, 195, 161, 116, 97, 110, 111, 115, 49, 49, 48, 47, 6, 3, 85,
        4, 3, 12, 40, 76, 97, 32, 70, 195, 161, 98, 114, 105, 99, 97, 32, 100, 101, 32, 80, 108,
        195, 161, 116, 97, 110, 111, 115, 32, 73, 110, 116, 101, 114, 109, 101, 100, 105, 97, 116,
        101, 32, 67, 65, 48, 30, 23, 13, 50, 53, 48, 56, 49, 51, 49, 52, 53, 56, 52, 48, 90, 23,
        13, 51, 53, 48, 56, 49, 49, 49, 52, 53, 57, 52, 48, 90, 48, 27, 49, 25, 48, 23, 6, 3, 85,
        4, 3, 19, 16, 105, 116, 115, 97, 108, 108, 98, 114, 111, 107, 101, 110, 46, 99, 111, 109,
        48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3,
        66, 0, 4, 65, 203, 37, 195, 17, 244, 252, 127, 57, 240, 189, 145, 113, 66, 58, 172, 101,
        61, 238, 25, 177, 6, 189, 193, 109, 213, 242, 99, 48, 199, 60, 29, 12, 43, 199, 236, 245,
        159, 91, 235, 138, 161, 254, 203, 63, 15, 87, 103, 161, 117, 126, 100, 211, 195, 86, 49,
        27, 83, 89, 231, 161, 143, 165, 65, 163, 129, 233, 48, 129, 230, 48, 14, 6, 3, 85, 29, 15,
        1, 1, 255, 4, 4, 3, 2, 7, 128, 48, 29, 6, 3, 85, 29, 37, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5,
        5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 220,
        141, 182, 39, 82, 120, 88, 76, 253, 162, 67, 219, 203, 43, 224, 87, 104, 110, 43, 142, 48,
        31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 32, 108, 142, 207, 228, 33, 167, 255, 237,
        35, 200, 61, 55, 15, 119, 129, 132, 113, 14, 21, 48, 27, 6, 3, 85, 29, 17, 4, 20, 48, 18,
        130, 16, 105, 116, 115, 97, 108, 108, 98, 114, 111, 107, 101, 110, 46, 99, 111, 109, 48,
        88, 6, 12, 43, 6, 1, 4, 1, 130, 164, 100, 198, 40, 64, 1, 4, 72, 48, 70, 2, 1, 1, 4, 20,
        100, 111, 109, 64, 105, 116, 115, 97, 108, 108, 98, 114, 111, 107, 101, 110, 46, 99, 111,
        109, 4, 43, 108, 104, 77, 88, 53, 54, 85, 81, 85, 66, 53, 101, 50, 115, 111, 71, 88, 115,
        55, 100, 81, 112, 78, 112, 95, 45, 99, 111, 95, 65, 83, 55, 116, 118, 74, 104, 66, 107, 45,
        104, 113, 73, 107, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 72, 0, 48, 69, 2, 32,
        13, 66, 176, 173, 88, 141, 30, 140, 88, 114, 201, 215, 41, 178, 186, 144, 230, 244, 165,
        47, 110, 143, 33, 96, 99, 186, 177, 44, 23, 184, 189, 39, 2, 33, 0, 196, 215, 99, 22, 117,
        28, 241, 129, 103, 141, 230, 96, 70, 132, 116, 196, 120, 237, 137, 80, 148, 220, 48, 43,
        238, 55, 201, 48, 193, 70, 7, 123,
    ];

    /// Encode and then decode `v`, returning the result.
    fn round_trip(v: &v1::ServerToClient) -> Result<ServerToClient, DecodingError> {
        ServerToClient::try_from(rc_x509_proto::encode(v).as_slice())
    }

    #[test]
    fn test_bad_wire_encoding() {
        let got = ServerToClient::try_from([42].as_slice());
        assert_matches!(got, Err(DecodingError::Wire(_)));
    }

    #[test]
    fn test_no_message() {
        let got = round_trip(&v1::ServerToClient { message: None });
        assert_matches!(got, Err(DecodingError::NoMessage));
    }

    /// Generate a [`ServerToClient`] messages that should successfully encode &
    /// decode (always including an inner message).
    fn arbitrary_server_to_client() -> impl Strategy<Value = v1::ServerToClient> {
        any::<v1::server_to_client::Message>()
            .prop_map(|mut v| {
                if let Message::CertificatePush(certificate) = &mut v {
                    // Always return a valid certificate.
                    certificate.der = SAMPLE_CERT_DER.to_owned();
                };

                v
            })
            .prop_map(|v| v1::ServerToClient { message: Some(v) })
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
