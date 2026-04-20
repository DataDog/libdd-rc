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

use std::{fmt::Display, ops::RangeInclusive};

use bytes::Bytes;
use x509_parser::prelude::X509Certificate;

use crate::{cached_string_repr::CachedStringRepr, hex::colon_string};

/// The allowable [`SerialNumber`] byte lengths.
const VALID_LENGTHS: RangeInclusive<usize> = 1..=20;

/// A [`Certificate`] serial number, potentially non-unique, set by the
/// certificate issuer.
///
/// X509 serial numbers are variable length byte arrays defined in RFC 5280 as
/// up to 20 bytes ("octets"):
///
/// > Certificate users MUST be able to handle serialNumber values up to 20
/// > octets.  Conforming CAs MUST NOT use serialNumber values longer than 20
/// > octets.
///
/// This implementation accepts a serial number of arbitrary length as a byte
/// array (as apposed to a using a fixed sized integer) up to a maximum of the
/// specified 20 bytes. Users of this type MUST account for the variable length
/// nature when storing or transmitting this value.
///
/// When rendered to a string (with [`Display`] or
/// [`SerialNumber::as_hex_str()`]) this type formats the serial number as a
/// colon delimited, lowercase hex string following the convention of the
/// OpenSSL representation of serial numbers (example:
/// `cc:cb:0f:63:f1:63:5e:f1:0e:26:e8:82:f7:7a:6e:f9`).
///
/// # Not Uniquely Identifying
///
/// Serial numbers are set by the certificate issuer. A certificate issuer
/// SHOULD use a unique serial number for each certificate it issues, but code
/// MUST NOT rely on a [`SerialNumber`] to uniquely identify a specific
/// certificate as it can be re-used if the issuer is compromised.
///
/// [`Certificate`]: super::Certificate
#[derive(Debug, Clone)] // NOTE: no PartialEq - not unique, do not compare.
pub struct SerialNumber {
    /// The raw BER serial bytes (a variable-length ASN.1 `INTEGER`).
    ///
    /// Invariant: immutable to ensure the cached rendering of the serial number
    /// remains in-sync.
    bytes: Bytes,

    /// A lazily-rendered string representation of `bytes`.
    ///
    /// See [`Self::as_hex_str()`] for initialisation.
    rendered: CachedStringRepr,
}

impl SerialNumber {
    /// Construct a new [`SerialNumber`] from a raw byte array.
    ///
    /// # Panics
    ///
    /// This constructor panics if `value` is empty, or if the length exceeds 20
    /// bytes.
    fn new(value: impl Into<Bytes>) -> Self {
        let bytes = value.into();

        // Correctness: reject out-of-spec serial numbers to bound the data
        // size of a serial number.
        assert!(
            VALID_LENGTHS.contains(&bytes.len()),
            "serial number of length {} is invalid",
            bytes.len()
        );

        Self {
            bytes,
            rendered: Default::default(),
        }
    }

    /// Render the [`SerialNumber`] as a lowercase hex string delimited by
    /// colons in the style of OpenSSL.
    ///
    /// Example: `cc:cb:0f:63:f1:63:5e:f1:0e:26:e8:82:f7:7a:6e:f9`
    ///
    /// This value is lazily rendered and cached for reuse.
    pub fn as_hex_str(&self) -> &str {
        self.rendered.get_or_init(|| colon_string(&self.bytes))
    }

    /// Return the raw serial number bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl Display for SerialNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_hex_str())
    }
}

impl<'a> From<&'a SerialNumber> for rcgen::SerialNumber {
    fn from(value: &'a SerialNumber) -> Self {
        Self::from_slice(value.as_bytes())
    }
}

impl<'a> From<&'a X509Certificate<'a>> for SerialNumber {
    fn from(cert: &'a X509Certificate<'a>) -> Self {
        Self::new(cert.raw_serial().to_vec())
    }
}

/// Render a [`SerialNumber`] as an encoded string in structured logging.
impl valuable::Valuable for SerialNumber {
    fn as_value(&self) -> valuable::Value<'_> {
        valuable::Value::String(self.as_hex_str())
    }

    fn visit(&self, visit: &mut dyn valuable::Visit) {
        visit.visit_value(self.as_value());
    }
}

#[cfg(test)]
mod tests {
    use crate::valuable_assert::assert_valuable_repr;

    use super::*;

    use proptest::prelude::*;
    use static_assertions::assert_not_impl_any;

    // Why: a SerialNumber can be set to anything by the issuer, making it
    // unreliable as a unique identifier, and should not be used to compare two
    // certificates for equality.
    assert_not_impl_any!(SerialNumber: PartialEq, Eq);

    #[test]
    fn test_fixture() {
        let hex_str = "cc:cb:0f:63:f1:63:5e:f1:0e:26:e8:82:f7:7a:6e:f9";

        let raw = hex::decode(hex_str.replace(':', "")).expect("valid hex");
        let sn = SerialNumber::new(raw.clone());

        assert_eq!(sn.to_string(), hex_str);
        assert_eq!(sn.as_hex_str(), hex_str);
        assert_eq!(sn.as_bytes(), &raw);
    }

    #[test]
    #[should_panic(expected = "serial number of length 0 is invalid")]
    fn test_empty() {
        let _sn = SerialNumber::new([].as_slice());
    }

    #[test]
    #[should_panic(expected = "serial number of length 21 is invalid")]
    fn test_too_long() {
        let _sn = SerialNumber::new(
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            ]
            .as_slice(),
        );
    }

    /// Assert how a serial number appears in structured logs.
    #[test]
    fn test_valuable_repr() {
        let sn = SerialNumber::new(
            [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
            ]
            .as_slice(),
        );

        assert_valuable_repr(
            &sn,
            "01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14\n",
        );
    }

    proptest! {
        #[test]
        fn prop_render_serial_number(
            value in prop::collection::vec(any::<u8>(), 1..20), // RFC 5280: 20 max
        ) {
            let serial = SerialNumber::new(value.clone());
            let rendered = serial.as_hex_str();

            let rcgen_serial = rcgen::SerialNumber::from(&serial);
            let rcgen_rendered = rcgen_serial.to_string();

            // Invariant: the rendered version matches the OpenSSL convention as
            // implemented by the rcgen type.
            assert_eq!(rendered, rcgen_rendered);

            // Invariant: the Display impl uses the same OpenSSL convention.
            assert_eq!(serial.to_string(), rendered);

            // Invariant: the byte accessor returns the raw serial bytes.
            assert_eq!(serial.as_bytes(), &value);
        }
    }
}
