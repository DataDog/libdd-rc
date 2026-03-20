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

use bytes::Bytes;
use pem as pem_crate;
use thiserror::Error;
use valuable::Valuable;
use x509_parser::{
    error::{PEMError, X509Error},
    nom::Parser,
    pem::Pem,
    prelude::X509CertificateParser,
};

use crate::{
    certificate::{Fingerprint, SerialNumber},
    keys::PublicKey,
};

/// A [`Certificate`] cannot be parsed from the invalid PEM data provided.
#[derive(Debug, Error)]
pub enum InvalidPem {
    /// The provided PEM contained no PEM.
    #[error("no PEM block found")]
    NoPEM,

    /// The PEM was not valid PEM.
    #[error("invalid PEM block: {0}")]
    DeserialisePEM(#[from] PEMError),

    /// The PEM was valid, but the encoded certificate was not.
    #[error("pem deserialised to invalid x509 cert: {0}")]
    ParseX509(#[from] x509_parser::nom::Err<X509Error>),

    /// After parsing the X509 certificate, there was unparsed data remaining
    /// (parser error).
    #[error("excess der bytes")]
    ExcessDER,

    /// More than one PEM-encoded something was provided.
    #[error("expected 1 PEM block but more provided")]
    TooManyBlocks,
}

/// An X509 [`Certificate`].
///
/// # Untrusted
///
/// A [`Certificate`] is untrusted input: it cannot be determined if the
/// certificate is from a trusted source and / or modified by an attacker unless
/// verified to cryptographically chain to a trust anchor / known root.
#[derive(Debug, Clone, Valuable)]
pub struct Certificate {
    /// DER encoded certificate.
    #[valuable(skip)]
    der: Bytes,

    /// A copy of the raw public key DER bytes in `cert`.
    #[valuable(skip)]
    public_key_der: Bytes,

    /// The parsed [`SerialNumber`] for this certificate.
    serial_number: SerialNumber,

    /// The parsed [`Fingerprint`] for this certificate.
    fingerprint: Fingerprint,
}

impl Certificate {
    /// Construct this certificate from a PEM string.
    pub fn from_pem(pem: &[u8]) -> Result<Self, InvalidPem> {
        let mut pem_iter = Pem::iter_from_buffer(pem);
        let pem = pem_iter.next().ok_or(InvalidPem::NoPEM)??;

        // It is an error to provide multiple certificates to this constructor.
        if pem_iter.next().is_some() {
            return Err(InvalidPem::TooManyBlocks);
        }

        let (rem, cert) = X509CertificateParser::new()
            .with_deep_parse_extensions(false) // Skip parsing unnecessary data.
            .parse(&*pem.contents)?;
        if !rem.is_empty() {
            // The provided PEM has trailing data after parsing the certificate.
            return Err(InvalidPem::ExcessDER);
        }

        let der = Bytes::copy_from_slice(cert.as_raw());
        let fingerprint = Fingerprint::from(&cert);
        let serial_number = SerialNumber::from(&cert);

        // Extract the raw public key DER bytes.
        let public_key_der = Bytes::from(cert.public_key().subject_public_key.data.to_vec());

        Ok(Self {
            der,
            serial_number,
            fingerprint,
            public_key_der,
        })
    }

    /// Return the raw DER bytes for this certificate.
    pub fn as_der(&self) -> Bytes {
        self.der.clone() // ref copy
    }

    /// Return this [`Certificate`] as a PEM string.
    pub fn generate_pem(&self) -> String {
        let pem = pem_crate::Pem::new("CERTIFICATE", self.der.as_ref());
        pem_crate::encode(&pem)
    }

    /// Return the serial number of this certificate.
    pub fn serial_number(&self) -> &SerialNumber {
        &self.serial_number
    }

    /// Return the unique fingerprint of this certificate.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }
    /// Return the [`PublicKey`] embedded in this [`Certificate`].
    pub fn public_key<'a>(&'a self) -> PublicKey<'a> {
        PublicKey::new(self.public_key_der.as_ref())
    }
}

impl From<rcgen::Certificate> for Certificate {
    fn from(value: rcgen::Certificate) -> Self {
        Certificate::from_pem(value.pem().as_bytes()).expect("valid cert round-trip")
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;

    use crate::valuable_assert::assert_valuable_repr;

    use super::*;

    use proptest::prelude::*;
    use valuable::Valuable;

    /// An PEM-encoded example leaf certificate for testing (missing PEM
    /// headers).
    ///
    /// ```text
    ///   Serial: 00:e2:7b:94:b7:3c:3d:08:ba:df:45:8d:56:7a:a5:e1:64
    ///   Valid: 2025-08-13 14:58 UTC to 2035-08-11 14:59 UTC
    ///   Signature: ECDSA-SHA256
    ///   Subject Info:
    ///           CommonName: itsallbroken.com
    ///   Issuer Info:
    ///           Organization: La Fábrica de Plátanos
    ///           CommonName: La Fábrica de Plátanos Intermediate CA
    ///   Subject Key ID: DC:8D:B6:27:52:78:58:4C:FD:A2:43:DB:CB:2B:E0:57:68:6E:2B:8E
    ///   Authority Key ID: 20:6C:8E:CF:E4:21:A7:FF:ED:23:C8:3D:37:0F:77:81:84:71:0E:15
    ///   Key Usage:
    ///           Digital Signature
    ///   Extended Key Usage:
    ///           Server Auth
    ///           Client Auth
    ///   DNS Names:
    ///           itsallbroken.com
    /// ```
    const CERT_PEM_DATA: &str = "\
MIICWjCCAgCgAwIBAgIRAOJ7lLc8PQi630WNVnql4WQwCgYIKoZIzj0EAwIwVjEh
MB8GA1UECgwYTGEgRsOhYnJpY2EgZGUgUGzDoXRhbm9zMTEwLwYDVQQDDChMYSBG
w6FicmljYSBkZSBQbMOhdGFub3MgSW50ZXJtZWRpYXRlIENBMB4XDTI1MDgxMzE0
NTg0MFoXDTM1MDgxMTE0NTk0MFowGzEZMBcGA1UEAxMQaXRzYWxsYnJva2VuLmNv
bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEHLJcMR9Px/OfC9kXFCOqxlPe4Z
sQa9wW3V8mMwxzwdDCvH7PWfW+uKof7LPw9XZ6F1fmTTw1YxG1NZ56GPpUGjgekw
geYwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAdBgNVHQ4EFgQU3I22J1J4WEz9okPbyyvgV2huK44wHwYDVR0jBBgwFoAUIGyO
z+Qhp//tI8g9Nw93gYRxDhUwGwYDVR0RBBQwEoIQaXRzYWxsYnJva2VuLmNvbTBY
BgwrBgEEAYKkZMYoQAEESDBGAgEBBBRkb21AaXRzYWxsYnJva2VuLmNvbQQrbGhN
WDU2VVFVQjVlMnNvR1hzN2RRcE5wXy1jb19BUzd0dkpoQmstaHFJazAKBggqhkjO
PQQDAgNIADBFAiANQrCtWI0ejFhyydcpsrqQ5vSlL26PIWBjurEsF7i9JwIhAMTX
YxZ1HPGBZ43mYEaEdMR47YlQlNwwK+43yTDBRgd7\
";

    #[test]
    fn test_fixture() {
        let pem =
            format!("-----BEGIN CERTIFICATE-----\n{CERT_PEM_DATA}\n-----END CERTIFICATE-----");

        let cert = Certificate::from_pem(pem.as_bytes()).expect("valid PEM");

        assert_eq!(
            cert.serial_number().as_hex_str(),
            "00:e2:7b:94:b7:3c:3d:08:ba:df:45:8d:56:7a:a5:e1:64"
        );

        // Fixture value extracted using OpenSSL:
        //
        //   % openssl x509 -in cert.pem -pubkey -noout | \
        //      openssl pkey -pubin -outform DER | \
        //      openssl dgst -sha256 -hex
        //
        // Converted from hex to decimal array for consistency with assert
        // output.
        assert_eq!(
            *cert.public_key().key_id(),
            [
                79, 76, 105, 90, 163, 235, 170, 81, 228, 220, 126, 244, 31, 241, 56, 133, 220, 5,
                215, 45, 202, 124, 72, 64, 131, 33, 152, 138, 94, 248, 14, 204
            ]
        );
    }

    /// Return a [`Certificate`] from [`CERT_PEM_DATA`].
    fn cert_fixture() -> Certificate {
        let pem =
            format!("-----BEGIN CERTIFICATE-----\n{CERT_PEM_DATA}\n-----END CERTIFICATE-----");

        Certificate::from_pem(pem.as_bytes()).expect("valid PEM")
    }

    #[test]
    fn test_valuable_repr() {
        let cert = cert_fixture();

        #[derive(Valuable)]
        struct Wrapper {
            cert: Certificate,
        }

        // Wrap the Certificate struct to capture the struct name in the
        // rendered output (otherwise only fields are captured).
        let cert = Wrapper { cert };

        assert_valuable_repr(
            &cert,
            "\
- cert:
    Certificate {}:
        - serial_number:
            00:e2:7b:94:b7:3c:3d:08:ba:df:45:8d:56:7a:a5:e1:64
        - fingerprint:
            49:ef:bb:e5:7f:3d:ff:9c:6d:b5:6a:15:b7:24:ba:8b:78:76:9c:16:a6:58:75:f9:b7:76:ae:ee:21:53:e5:e5
",
        );
    }

    #[test]
    fn test_fingerprint_fixture() {
        let cert = cert_fixture();

        assert_eq!(
            cert.fingerprint().as_hex_str(),
            "49:ef:bb:e5:7f:3d:ff:9c:6d:b5:6a:15:b7:24:ba:8b:78:76:9c:16:a6:58:75:f9:b7:76:ae:ee:21:53:e5:e5"
        );
    }

    #[test]
    fn test_round_trip_pem() {
        let cert = cert_fixture();

        let got = Certificate::from_pem(cert.generate_pem().as_bytes()).expect("valid cert");
        assert_eq!(got.der, cert.der);
        assert_eq!(got.public_key_der, cert.public_key_der);
        assert_eq!(got.fingerprint(), cert.fingerprint());
    }

    /// Fragments of a potentially invalid PEM block.
    #[derive(Debug, Clone)]
    enum PemPart {
        /// The opening PEM header.
        Start,
        /// The closing PEM footer.
        End,
        // Random string data.
        RandomData(String),
        // A valid PEM block for a certificate.
        ValidCertData,
    }

    // Render the PEM block fragments.
    impl Display for PemPart {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                PemPart::Start => f.write_str("-----BEGIN CERTIFICATE-----\n"),
                PemPart::End => f.write_str("-----END CERTIFICATE-----\n"),
                PemPart::RandomData(s) => f.write_str(s),
                PemPart::ValidCertData => f.write_str(CERT_PEM_DATA),
            }
        }
    }

    // Yield an arbitrary [`PemPart`].
    fn arbitrary_pem_part() -> impl Strategy<Value = PemPart> {
        prop_oneof![
            Just(PemPart::Start),
            Just(PemPart::End),
            any::<String>().prop_map(PemPart::RandomData),
            Just(PemPart::ValidCertData),
        ]
    }

    proptest! {
        /// Generate strings from the `PemPart` fragments and attempt to parse
        /// it as a `Certificate`.
        #[test]
        fn prop_from_pem(
            parts in prop::collection::vec(arbitrary_pem_part(), 0..5),
        ) {
            prop_from_pem_test(parts);
        }

        /// Parse a Certificate from random invalid bytes, ensuring no panic
        /// occurs.
        #[test]
        fn prop_invalid_pem_bytes(
            binary in prop::collection::vec(any::<u8>(), 0..200),
        ) {
            let _ = Certificate::from_pem(&binary).expect_err("non-pem input");
        }
    }

    fn prop_from_pem_test(parts: Vec<PemPart>) {
        // Build a string from the randomised parts.
        let pem: String = parts.iter().map(ToString::to_string).collect();

        // Attempt to parse the certificate from this string.
        match Certificate::from_pem(pem.as_bytes()) {
            Ok(_) => {
                // Continue and verify below.
            }
            Err(_) => {
                // Did not accept input, and did not panic.
                return;
            }
        }

        // The success case must be the only valid sequence of PEM fragments.
        //
        // (technically the random string fragment might produce a completely
        // valid PEM certificate string, but the probability is so low it's
        // effectively zero).
        assert!(matches!(
            parts.as_slice(),
            [PemPart::Start, PemPart::ValidCertData, PemPart::End]
        ));
    }
}
