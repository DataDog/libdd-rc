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
    /// Construct a [`MemoryCertCache`] that will hold at most `capacity` number
    /// of entries (best effort bound).
    ///
    /// Evictions when the cache bound is reached are probabilistic, using a
    /// hybrid of LFU and LRU ([TinyLFU]).
    ///
    /// [TinyLFU]: https://arxiv.org/abs/1512.00727
    pub fn new(capacity: u64) -> Self {
        Self {
            certs: Cache::builder()
                .max_capacity(capacity)
                .time_to_idle(PURGE_AFTER)
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
            let cache = MemoryCertCache::new(ops.len() as u64 + 1);

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

        /// Verify the capacity bounds and eviction of the cache.
        #[test]
        fn prop_eviction(
            // A set of indexes into `CERT_POOL`, yielding a set of distinct
            // certificates that may be smaller or (usually) larger than `CAP`.
            idx in prop::collection::hash_set(0..POOL_SIZE, 1..=POOL_SIZE),
        ) {
            let certs = idx.iter().map(|&i| Arc::clone(&CERT_POOL[i])).collect::<Vec<_>>();

            let cache = MemoryCertCache::new(CAP as _);

            // Populate the cache.
            for cert in &certs {
                cache.insert(UntrustedCert::from(cert.cert().clone()));
            }

            // Drive the deferred cache maintenance (including eviction) to
            // completion, as it is otherwise performed asynchronously.
            cache.certs.sync();

            // Extract both the inputs and cached values as comparable types.
            //
            // All inputs are distinct, so no insert overwrote another entry.
            let cached_entries = cache
                .certs
                .iter()
                .map(|v| Arc::clone(v.value()))
                .collect::<Vec<_>>();
            let inputs = certs
                .iter()
                .map(|v| Arc::new(UntrustedCert::from(v.cert().clone())))
                .collect::<Vec<_>>();

            // Assert the expected content.
            if inputs.len() <= CAP {
                // Within the capacity bounds, all entries should be retained.
                assert_eq!(cached_entries.len(), inputs.len());

                for want in &inputs {
                    assert!(cached_entries.contains(want));
                }
            } else {
                // In excess of the bounds, some entries must be dropped to
                // respect the capacity bound.
                assert!(cached_entries.len() <= CAP, "cached {} entries", cached_entries.len());
                assert!(!cached_entries.is_empty());
            }

            // Whichever entries were retained, they must be a subset of the
            // inserted certificates - which entries survive eviction is a
            // probabilistic property of TinyLFU and is not asserted.
            for got in &cached_entries {
                assert!(inputs.contains(got));
            }
        }
    }
}
