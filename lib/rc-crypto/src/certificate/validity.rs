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
use std::{fmt::Display, ops::RangeInclusive};
use x509_parser::{prelude::X509Certificate, time::ASN1Time};

use crate::cached_string_repr::CachedStringRepr;

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
    rendered: CachedStringRepr,
}

impl Validity {
    /// Construct a new [`Validity`] from the x509_parser Validity representation.
    ///
    /// x509_parser represents timestamps as [`ASN1Time`], which exposes the
    /// underlying Unix timestamp in seconds. Each value is converted to a
    /// [`jiff::Timestamp`] for ergonomic use.
    ///
    /// # Errors
    ///
    /// Returns an error if either timestamp in `value` is outside of the valid
    /// [`jiff::Timestamp`] range.
    fn new(value: &x509_parser::certificate::Validity) -> Result<Self, jiff::Error> {
        let not_before = asn1_to_timestamp(value.not_before)?;
        let not_after = asn1_to_timestamp(value.not_after)?;

        Ok(Self {
            not_before,
            not_after,
            rendered: Default::default(),
        })
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

    /// Return the validity as a RangeInclusive.
    ///
    /// From [RFC 5280 § 4.1.2.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5
    /// the validity period for a certificate is the period of time from
    /// notBefore through notAfter, inclusive
    pub fn range(&self) -> RangeInclusive<Timestamp> {
        RangeInclusive::new(self.not_before, self.not_after)
    }
}

impl Display for Validity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_display_str().fmt(f)
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

impl<'a> TryFrom<&'a X509Certificate<'a>> for Validity {
    type Error = jiff::Error;

    fn try_from(cert: &'a X509Certificate<'a>) -> Result<Self, Self::Error> {
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
    use proptest::prelude::*;

    use super::*;

    fn make_validity(not_before_secs: i64, not_after_secs: i64) -> Validity {
        Validity {
            not_before: Timestamp::from_second(not_before_secs).unwrap(),
            not_after: Timestamp::from_second(not_after_secs).unwrap(),
            rendered: Default::default(),
        }
    }

    #[test]
    fn test_fixture() {
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

    // Verify that trying to convert a timestamp outside of [`jiff::Timestamp`]'s
    // MIN & MAX bounds returns an error
    #[test]
    fn test_timestamp_out_of_range() {
        // Set timestamp to +1 of the jiff::Timestamp::MAX
        let jiff_beyond_max = Timestamp::MAX.as_second() + 1;
        assert!(Timestamp::from_second(jiff_beyond_max).is_err());
        let asn1_beyond_max = ASN1Time::from_timestamp(jiff_beyond_max).unwrap();
        assert!(asn1_to_timestamp(asn1_beyond_max).is_err());

        // Set timestamp to -1 of the jiff::Timestamp::MIN
        let jiff_before_min = Timestamp::MIN.as_second() - 1;
        assert!(Timestamp::from_second(jiff_before_min).is_err());
        let asn1_before_min = ASN1Time::from_timestamp(jiff_before_min).unwrap();
        assert!(asn1_to_timestamp(asn1_before_min).is_err());
    }

    proptest! {
        /// This tests both timestamps that are in AND out of the Validity range.
        /// For a given timestamp and validity range (not_before, not_after), checks
        /// whether timestamp is 'contained' within the range.
        #[test]
        fn prop_timestamp_in_validity_range(
            not_before in 0i64..=3_000_000_000i64,
            not_after in 0i64..=3_000_000_000i64,
            ts_secs in 0i64..=4_000_000_000i64,
        ) {
            let v = make_validity(not_before, not_after);
            let ts = Timestamp::from_second(ts_secs).unwrap();

            // Verify that the RangeInclusive of not_before and not_after
            // correctly catorizes whether the timestamp is within the validity range.
            prop_assert_eq!(v.range().contains(&ts), not_before <= ts_secs && ts_secs <= not_after);
        }
    }
}
