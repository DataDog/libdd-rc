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

//! A compact, probabilistic summary of a set of [`CertId`].

use rc_crypto::certificate::id::CertId;
use twox_hash::XxHash3_64;
use xorf::{BinaryFuse8, Filter};

/// A probabilistic set holding some number of [`CertId`].
///
/// The [`CertId`] is an untrusted value, and in addition the set of [`CertId`]
/// is also easily manipulated into returning false positives.
///
/// Querying this set has a false-positive rate of ~0.4%.
///
/// # Filter Size
///
/// The filter uses approximately 9 bits per certificate for large sets, rising
/// to 12 bits per certificate for sets of a few thousand or less (see tests).
#[derive(Debug, Clone)]
pub struct CertFuseFilter {
    filter: BinaryFuse8,
}

impl CertFuseFilter {
    /// Construct a [`CertFuseFilter`] containing all `cert_ids`.
    ///
    /// # Distinct Keys
    ///
    /// All `cert_ids` MUST be distinct - providing duplicate [`CertId`] values
    /// panics in debug builds.
    pub fn new<'a>(cert_ids: impl IntoIterator<Item = &'a CertId>) -> Option<Self> {
        let keys = cert_ids.into_iter().map(make_key).collect::<Vec<_>>();

        // Construction of a filter from distinct keys only fails with near
        // impossible probability, but it is a technical possibility.
        let filter = BinaryFuse8::try_from(keys).ok()?;

        Some(Self { filter })
    }

    /// Returns true if a certificate identified by `cert_id` was (probably)
    /// present in the [`CertCache`] when this filter was
    /// constructed.
    ///
    /// Never returns a false negative, but may return a false positive.
    ///
    /// [`CertCache`]: super::CertCache
    pub fn contains(&self, cert_id: &CertId) -> bool {
        self.filter.contains(&make_key(cert_id))
    }
}

/// Derive the filter key for `cert_id`.
///
/// This maps the full variable length `cert_id` into a fixed size u64. This
/// mixing uses a static xxHash seed key so it is portable between machines,
/// however this means collisions are relatively easy to construct for a
/// malicious attacker.
fn make_key(cert_id: &CertId) -> u64 {
    XxHash3_64::oneshot(cert_id.as_dangerous_comparable().as_bytes())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use xorf::DmaSerializable;

    use super::*;

    /// Return the serialised byte size of `filter` (the fixed size descriptor
    /// and the variable length fingerprint array).
    fn byte_size(filter: &CertFuseFilter) -> usize {
        BinaryFuse8::DESCRIPTOR_LEN + filter.filter.len()
    }

    /// Generate `n` distinct [`CertId`] values.
    fn cert_ids(n: usize) -> Vec<CertId> {
        (0..n as u128)
            .map(|i| CertId::try_from(i.to_be_bytes().as_slice()).unwrap())
            .collect()
    }

    /// Assert the serialised filter byte size for `n` certificates.
    fn assert_byte_size(n: usize, want: usize) -> f64 {
        let filter = CertFuseFilter::new(&cert_ids(n)).expect("filter construction");
        assert_eq!(byte_size(&filter), want);

        // Sanity check the upper bound bits per entry (excluding the fixed
        // descriptor).
        let bits_per_entry = (filter.filter.len() * 8) as f64 / n as f64;
        assert!(bits_per_entry < 13.0, "bits per entry: {bits_per_entry}");
        bits_per_entry
    }

    /// For a SAMPLE of 500 values, how big is the filter (approximately)?
    #[test]
    fn test_byte_size_500() {
        let bits_per_entry = assert_byte_size(500, 788);
        assert_eq!(bits_per_entry.round(), 12.0);
    }

    #[test]
    fn test_byte_size_1000() {
        let bits_per_entry = assert_byte_size(1_000, 1_428);
        assert_eq!(bits_per_entry.round(), 11.0);
    }

    #[test]
    fn test_byte_size_3000() {
        let bits_per_entry = assert_byte_size(3_000, 4_116);
        assert_eq!(bits_per_entry.round(), 11.0);
    }

    #[test]
    fn test_empty() {
        let filter = CertFuseFilter::new([]).expect("filter construction");
        assert_eq!(byte_size(&filter), 20 + 12);
    }

    #[test]
    fn test_single() {
        let ids = cert_ids(1);
        let filter = CertFuseFilter::new(&ids).expect("filter construction");
        assert!(filter.contains(&ids[0]));
        assert_eq!(byte_size(&filter), 20 + 12);
    }

    proptest! {
        /// No false negatives for any set of distinct cert IDs.
        #[test]
        fn prop_no_false_negatives(
            ids in prop::collection::hash_set(any::<u128>(), 0..500),
        ) {
            let ids = ids
                .into_iter()
                .map(|v| CertId::try_from(v.to_be_bytes().as_slice()).unwrap())
                .collect::<Vec<_>>();

            let filter = CertFuseFilter::new(&ids).expect("filter construction");
            for id in &ids {
                assert!(filter.contains(id));
            }
        }
    }
}
