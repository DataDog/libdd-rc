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

//! An in-memory cache used to hold [`Certificate`] instances for trust
//! operations.

use std::{sync::Arc, time::Duration};

use mini_moka::sync::Cache;
use rc_crypto::certificate::id::{CertId, DangerousComparableId};

use crate::{cert::UntrustedCert, trust_store::CertCache};

/// How long a single cached entry lives if it remains unused.
const PURGE_AFTER: Duration = Duration::from_hours(24);

/// Stores [`Certificate`] instances in memory, providing a [`CertCache`]
/// implementation.
#[derive(Debug)]
pub struct MemoryCertCache {
    certs: Cache<DangerousComparableId<'static, CertId>, Arc<UntrustedCert>>,
}

impl MemoryCertCache {
    /// Construct a [`MemoryCertCache`] that will place a best effort upper
    /// bound on approximated memory usage to `approx_max_bytes`.
    ///
    /// Evictions when the cache bound is reached are probabilistic, using a
    /// hybrid of LFU and LRU ([TinyLFU]).
    ///
    /// # Memory Usage
    ///
    /// The memory bound is approximate; the underlying implementation is best
    /// effort, and the entry memory estimator used is naively accounting for
    /// only the raw DER bytes and none of the values parsed from it or the heap
    /// overhead necessary to store it, nor can it account for memory
    /// fragmentation or allocation bucketing.
    ///
    /// Estimator: `Certificate DER bytes + 25%`.
    ///
    /// It is useful as a rough safety bound to prevent unbounded growth only.
    ///
    /// [TinyLFU]: https://arxiv.org/abs/1512.00727
    pub fn new(approx_max_bytes: u64) -> Self {
        Self {
            certs: Cache::builder()
                .max_capacity(approx_max_bytes)
                .time_to_idle(PURGE_AFTER)
                .weigher(|_id, cert: &Arc<UntrustedCert>| -> u32 {
                    weight_estimator(cert.as_der_slice().len())
                })
                .build(),
        }
    }
}

impl CertCache for MemoryCertCache {
    fn insert(&self, cert: UntrustedCert) {
        let cert_id = cert.cert_id().as_dangerous_comparable().into_owned();
        let cert = Arc::new(cert);

        let cert_copy = Arc::clone(&cert);

        // NOTE: an attacker can forge a certificate that contains a duplicate
        // SKI (the value used as cert IDs) in order to evict other
        // certificates.
        self.certs.insert(cert_id, cert_copy);
    }

    fn get<'a>(&self, cert_id: &CertId) -> Option<Arc<UntrustedCert>> {
        let got = self
            .certs
            .get(&cert_id.as_dangerous_comparable().into_owned());

        if let Some(cert) = &got {
            // Invariant: any returned certificate MUST have the same cert ID as
            // the query value, else this mapping is invalid.
            assert_eq!(
                cert.cert_id().as_dangerous_comparable(),
                cert_id.as_dangerous_comparable()
            );
        }

        got
    }

    fn remove<'a>(&self, cert_id: &CertId) {
        self.certs
            .invalidate(&cert_id.as_dangerous_comparable().into_owned());
    }
}

/// Approximate the memory usage of `cert` for cache accounting purposes.
///
/// See [`MemoryCertCache::new()`].
fn weight_estimator(der_len: usize) -> u32 {
    // Approximately account for overhead by applying a 25% multiplier; the DER
    // slice is not the only data in an `UntrustedCert`.
    u32::try_from((der_len * 5) / 4).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, LazyLock},
    };

    use mini_moka::sync::ConcurrentCacheExt;
    use proptest::prelude::*;

    use crate::test_issuer::{CertBuilder, Identity, TestCA};

    use super::*;

    static CA: TestCA = TestCA::new();

    /// The cache capacity used by [`prop_eviction`].
    const CAP: usize = 10;

    /// The number of distinct certificates available to [`prop_eviction`],
    /// which must exceed [`CAP`] in order to drive evictions.
    const POOL_SIZE: usize = CAP * 3;

    /// A set of [`POOL_SIZE`] certificates, each with a distinct cert ID.
    ///
    /// Generated once, as certificate generation is relatively expensive.
    static CERT_POOL: LazyLock<Vec<Arc<Identity>>> = LazyLock::new(|| {
        (0..POOL_SIZE)
            .map(|i| {
                Arc::new(
                    CertBuilder::new_leaf(format!("Leaf {i}"), CA.root())
                        .san("us1.example.com")
                        .build(),
                )
            })
            .collect()
    });

    /// Return one of 4 random certificates.
    fn arbitrary_cert() -> impl Strategy<Value = Arc<Identity>> {
        let intermediate_a = Arc::new(
            CertBuilder::new_intermediate("Intermediate A", CA.root())
                .allowed_domain("ignored")
                .build(),
        );

        let intermediate_b = Arc::new(
            CertBuilder::new_intermediate("Intermediate B", CA.root())
                .allowed_domain("ignored")
                .build(),
        );

        let leaf_a = Arc::new(
            CertBuilder::new_leaf("Leaf A", CA.root())
                .san("us1.example.com")
                .build(),
        );

        let leaf_b = Arc::new(
            CertBuilder::new_leaf("Leaf B", &intermediate_a)
                .san("us1.example.com")
                .build(),
        );

        prop_oneof![
            Just(intermediate_a),
            Just(intermediate_b),
            Just(leaf_a),
            Just(leaf_b)
        ]
    }

    /// Generate completely random [`CertId`] values.
    fn arbitrary_cert_id() -> impl Strategy<Value = CertId> {
        any::<[u8; 32]>().prop_map(|v| CertId::try_from(v.as_slice()).unwrap())
    }

    #[derive(Debug, Clone)]
    enum Op {
        Insert(Box<UntrustedCert>),
        Get(CertId),
        Delete(CertId),
    }

    /// Generate an arbitrary [`Op`] that manipulates a `cert`, or a completely
    /// random [`CertId`].
    fn arbitrary_op(certs: impl Strategy<Value = Arc<Identity>>) -> impl Strategy<Value = Op> {
        certs.prop_flat_map(|v| {
            prop_oneof![
                // Operations on certs that may match an entry.
                3 => Just(Op::Insert(Box::new(UntrustedCert::from(v.cert().clone())))),
                3 => Just(Op::Get(v.cert().cert_id().to_owned())),
                3 => Just(Op::Delete(v.cert().cert_id().to_owned())),

                // Random key IDs that are not going to match an entry.
                1 => arbitrary_cert_id().prop_map(Op::Get),
                1 => arbitrary_cert_id().prop_map(Op::Delete),
            ]
        })
    }

    proptest! {
        /// Assert behavioural equality between a `HashMap` and an
        /// [`AcceptedCertCache`] for varying [`Op`] if there is no eviction.
        #[test]
        fn prop_ops(
            ops in prop::collection::vec(arbitrary_op(arbitrary_cert()), 1..20),
        ) {
            let mut control = HashMap::new();
            let cache = MemoryCertCache::new(5 * 1024 * 1024); // Big enough for all

            for op in ops {
                match op {
                    Op::Insert(cert) => {
                        control.insert(cert.cert_id().as_hex_str().to_string(), cert.clone());
                        cache.insert(*cert);
                    },
                    Op::Get(cert_id) => {
                        assert_eq!(
                            control.get(cert_id.as_hex_str()).map(|v| v.fingerprint().to_owned()),
                            cache.get(&cert_id).map(|v| v.fingerprint().to_owned()),
                        );
                    },
                    Op::Delete(cert_id) => {
                        let existed = cache.get(&cert_id);
                        cache.remove(&cert_id);
                        assert_eq!(
                            control.remove(cert_id.as_hex_str()).is_some(),
                            existed.is_some(),
                        );
                    },
                }
            }

            let cache_len = cache.certs.iter().count();

            assert_eq!(control.len(), cache_len);
            for v in cache.certs.iter() {
                assert_eq!(*v.key(), v.value().cert_id().as_dangerous_comparable());

                let control = control.get(v.value().cert_id().as_hex_str()).expect("control must contain cert");
                assert_eq!(control.fingerprint(), v.value().fingerprint());
            }
        }

        /// Verify the memory bounds and eviction of the cache.
        #[test]
        fn prop_eviction(
            certs in prop::collection::vec(arbitrary_cert(), 5..20),
            // The fraction of the total input weight the cache is allowed to
            // hold, as a percentage.
            capacity_pct in 0u64..=100,
        ) {
            let input = certs
                .iter()
                .map(|v| Arc::new(UntrustedCert::from(v.cert().clone())))
                .collect::<Vec<_>>();

            // Build a list of unique certificates, as later insertions of a
            // duplicate cert ID will overwrite earlier entries in the cert ID
            // keyed cache.
            let mut unique_inputs: Vec<Arc<UntrustedCert>> = Vec::new();
            for cert in input {
                unique_inputs.retain(|c: &Arc<UntrustedCert>| {
                    c.cert_id().as_dangerous_comparable() != cert.cert_id().as_dangerous_comparable()
                });
                unique_inputs.push(cert);
            }

            let total_weight: u64 = unique_inputs.iter().map(|v| u64::from(weight_estimator(v.as_der_slice().len()))).sum();
            let max_weight: u64 = unique_inputs
                .iter()
                .map(|v| u64::from(weight_estimator(v.as_der_slice().len())))
                .max()
                .expect("at least one input");

            // Scale the cache bound somewhere between "a single entry fits" and
            // "all entries fit".
            //
            // The bound is never less than the largest single entry, as an
            // entry that exceeds the cache capacity is never admitted.
            let cap = std::cmp::max(max_weight, (total_weight * capacity_pct) / 100);

            let cache = MemoryCertCache::new(cap);

            // Populate the cache.
            for cert in &certs {
                cache.insert(UntrustedCert::from(cert.cert().clone()));
            }

            // Forge a cleanup (if necessary).
            cache.certs.sync();

            let cached_entries = cache
                .certs
                .iter()
                .map(|v| Arc::clone(v.value()))
                .collect::<Vec<_>>();

            // The cache must stay within the configured memory bound.
            //
            // Admission & eviction is best effort and lags behind the
            // insertion of new entries, so allow an overshoot of a single
            // maximally sized entry.
            let cached_weight: u64 = cached_entries
                .iter()
                .map(|v| u64::from(weight_estimator(v.as_der_slice().len())))
                .sum();
            assert!(
                cached_weight <= cap + max_weight,
                "cached weight {cached_weight} exceeds bound {cap} (+{max_weight} slack)"
            );

            // Assert the expected content.
            if total_weight <= cap {
                // Within the memory bounds, all entries should be retained.
                assert_eq!(cached_entries.len(), unique_inputs.len());

                for want in &unique_inputs {
                    assert!(cached_entries.contains(want));
                }
            } else if total_weight > cap + max_weight {
                // Sufficiently in excess of the bounds (accounting for the
                // eviction slack above) some entries must have been dropped to
                // stay within the memory bound.
                assert!(cached_entries.len() < unique_inputs.len());
            }
        }
    }

    /// A very rough estimation of the entry count for the cert cache.
    #[test]
    fn test_cert_cache_bounds() {
        // The byte size of a certificate sampled from production.
        //
        // This is the raw DER byte size - the actual memory usage will be
        // larger than this due to representation overhead and fragmentation.
        const APPROX_CERT_SIZE: usize = 500;

        // A 2MiB cache.
        const CAPACITY_BYTES: usize = 1024 * 1024 * 2;

        // Can hold this many certs (very roughly).
        let approx_count = CAPACITY_BYTES / weight_estimator(APPROX_CERT_SIZE) as usize;
        assert_eq!(approx_count, 3355);
    }
}
