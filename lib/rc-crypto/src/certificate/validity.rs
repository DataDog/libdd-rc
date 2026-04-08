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

use jiff::Timestamp;
use std::sync::OnceLock;
use x509_parser::{prelude::X509Certificate, time::ASN1Time};

/// The [`Validity`] is the time interval during which a [`Certificate`] is
/// considered valid.
///
/// An X.509 certificate validity period is defined in [RFC 5280 § 4.1.2.5] as
/// a `SEQUENCE` of two date-time values: `notBefore` and `notAfter`. The
/// certificate is considered valid only during the closed interval
/// `[notBefore, notAfter]`.
///
/// [`Certificate`]: super::Certificate
/// [RFC 5280 § 4.1.2.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5
#[derive(Debug, Clone)]
pub struct Validity {
    /// The earliest date and time at which the certificate is considered valid.
    not_before: Timestamp,

    /// The latest date and time at which the certificate is considered valid.
    not_after: Timestamp,

    /// A lazily-rendered string representation of `not_before` & `not_after`.
    ///
    /// See [`Self::as_display_str()`] for initialisation.
    rendered: OnceLock<String>,
}

impl Validity {
    /// Construct a new [`Validity`] from the x509_parser Validity representation.
    ///
    /// x509_parser represents timestamps as [`ASN1Time`], which exposes the
    /// underlying Unix timestamp in seconds. Each value is converted to a
    /// [`jiff::Timestamp`] for ergonomic use.
    ///
    /// # Panics
    ///
    /// Panics if either timestamp in `value` contains a seconds value outside
    /// the range supported by [`Timestamp`].
    fn new(value: &x509_parser::certificate::Validity) -> Self {
        let not_before = asn1_to_timestamp(value.not_before)
            .expect("x509 timestamp is within jiff's supported range");
        let not_after = asn1_to_timestamp(value.not_after)
            .expect("x509 timestamp is within jiff's supported range");

        Self {
            not_before,
            not_after,
            rendered: Default::default(),
        }
    }

    /// Return the [`Timestamp`] at which the certificate becomes valid.
    pub fn not_before_as_timestamp(&self) -> Timestamp {
        self.not_before
    }

    /// Return the [`Timestamp`] at which the certificate expires.
    pub fn not_after_as_timestamp(&self) -> Timestamp {
        self.not_after
    }

    /// Render `notBefore` and `notAfter` of [`Timestamp`] as a single string
    ///
    /// Example `2024-01-01T00:00:00Z..2025-01-01T00:00:00Z`
    ///
    /// This value is lazily rendered and cached for reuse.
    pub fn as_display_str(&self) -> &str {
        self.rendered
            .get_or_init(|| format!("{}..{}", self.not_before, self.not_after))
    }
}

/// Convert an [`ASN1Time`] to a [`Timestamp`] by extracting the underlying
/// Unix timestamp in seconds.
///
/// # Errors
///
/// Returns an error if the seconds value is outside the range supported by
/// [`Timestamp`] (approximately ±9999 years from the Unix epoch).
fn asn1_to_timestamp(timestamp: ASN1Time) -> Result<Timestamp, jiff::Error> {
    let secs = timestamp.timestamp();
    Timestamp::from_second(secs)
}

impl<'a> From<&'a X509Certificate<'a>> for Validity {
    fn from(cert: &'a X509Certificate<'a>) -> Self {
        Self::new(cert.validity())
    }
}

/// Render a [`Validity`] as an encoded string in structured logging.
impl valuable::Valuable for Validity {
    fn as_value(&self) -> valuable::Value<'_> {
        valuable::Value::String(self.as_display_str())
    }

    fn visit(&self, visit: &mut dyn valuable::Visit) {
        visit.visit_value(self.as_value());
    }
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use super::*;

    fn make_validity(not_before_secs: i64, not_after_secs: i64) -> Validity {
        Validity {
            not_before: Timestamp::from_second(not_before_secs).unwrap(),
            not_after: Timestamp::from_second(not_after_secs).unwrap(),
            rendered: Default::default(),
        }
    }

    #[test]
    fn test_valid_timestamps() {
        let not_before_secs = 1_000_000_000i64; // 2001-09-09T01:46:40Z
        let not_after_secs = 2_000_000_000i64; // 2033-05-18T03:33:20Z

        let v = make_validity(not_before_secs, not_after_secs);

        assert_eq!(
            v.not_before_as_timestamp(),
            Timestamp::from_second(not_before_secs).unwrap()
        );

        assert_eq!(
            v.not_after_as_timestamp(),
            Timestamp::from_second(not_after_secs).unwrap()
        );

        assert_eq!(
            v.as_display_str(),
            "2001-09-09T01:46:40Z..2033-05-18T03:33:20Z"
        );
    }

    #[test]
    fn test_timestamp_out_of_range() {
        use time::{PrimitiveDateTime, macros::offset};
        use x509_parser::time::ASN1Time;

        // PrimitiveDateTime::MAX (9999-12-31T23:59:59) with the most negative
        // UTC offset shifts the UTC-equivalent timestamp beyond jiff's maximum
        // of 9999-12-31T23:59:59Z, so asn1_to_timestamp must return a jiff::Error.
        let beyond_max = PrimitiveDateTime::MAX.assume_offset(offset!(-23:59:59));
        let err = asn1_to_timestamp(ASN1Time::new(beyond_max));
        assert!(err.is_err());

        // Similarly, PrimitiveDateTime::MIN (-9999-01-01T00:00:00) with the
        // most positive UTC offset shifts the UTC-equivalent below jiff's
        // minimum of -9999-01-01T00:00:00Z.
        let before_min = PrimitiveDateTime::MIN.assume_offset(offset!(+23:59:59));
        let err = asn1_to_timestamp(ASN1Time::new(before_min));
        assert!(err.is_err());
    }
}
