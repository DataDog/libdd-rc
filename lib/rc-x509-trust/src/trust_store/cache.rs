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

use std::sync::Arc;

use hashbrown::HashMap;

use rc_crypto::certificate::{
    Certificate,
    id::{CertId, DangerousComparableId},
};

use crate::trust_store::CertCache;

/// Stores [`Certificate`] instances in memory, providing a [`CertCache`]
/// implementation.
#[derive(Debug, Default)]
pub struct MemoryCertCache {
    certs: HashMap<DangerousComparableId<'static, CertId>, Arc<Certificate>>,
}

impl CertCache for MemoryCertCache {
    fn insert(&mut self, cert: Certificate) {
        let cert_id = cert.cert_id().as_dangerous_comparable().into_owned();
        let cert = Arc::new(cert);

        let cert_copy = Arc::clone(&cert);
        let removed = self.certs.insert(cert_id, cert_copy);

        // Invariant: if a cert previously existed under the provided key_id, it
        // MUST be the same certificate (as indicated by matching fingerprints).
        assert!(
            removed
                .map(|v| v.fingerprint() == cert.fingerprint())
                .unwrap_or(true)
        );
    }

    fn get<'a>(&self, cert_id: &CertId) -> Option<Arc<Certificate>> {
        let got = self.certs.get(cert_id).map(Arc::clone);

        if let Some(cert) = &got {
            // Invariant: any returned certificate MUST have the same cert ID as
            // the query value.
            assert_eq!(
                cert.cert_id().as_dangerous_comparable(),
                cert_id.as_dangerous_comparable()
            );
        }

        got
    }

    fn remove<'a>(&mut self, cert_id: &CertId) -> bool {
        let removed = self.certs.remove(cert_id);

        if let Some(cert) = &removed {
            // Invariant: any removed certificate MUST have the same cert ID as
            // the query value.
            assert_eq!(
                cert.cert_id().as_dangerous_comparable(),
                cert_id.as_dangerous_comparable()
            );
        }

        removed.is_some()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::test_issuer::{CertBuilder, Identity, TestCA};

    use super::*;

    static CA: TestCA = TestCA::new();

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
        prop_oneof![any::<[u8; 32]>().prop_map(|v| CertId::from(v.as_slice()))]
    }

    #[derive(Debug, Clone)]
    enum Op {
        Insert(Box<Certificate>),
        Get(CertId),
        Delete(CertId),
    }

    /// Generate an arbitrary [`Op`] that manipulates a `cert`, or a completely
    /// random [`CertId`].
    fn arbitrary_op(certs: impl Strategy<Value = Arc<Identity>>) -> impl Strategy<Value = Op> {
        certs.prop_flat_map(|v| {
            prop_oneof![
                // Operations on certs that may match an entry.
                3 => Just(Op::Insert(Box::new(v.cert().clone()))),
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
        /// [`AcceptedCertCache`] for varying [`Op`].
        #[test]
        fn prop_ops(
            ops in prop::collection::vec(arbitrary_op(arbitrary_cert()), 1..20),
        ) {
            let mut control = HashMap::new();
            let mut cache = MemoryCertCache::default();

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
                        assert_eq!(
                            control.remove(cert_id.as_hex_str()).is_some(),
                            cache.remove(&cert_id),
                        );
                    },
                }
            }

            assert_eq!(control.len(), cache.certs.len());
            for (id, cert) in cache.certs {
                assert_eq!(id, cert.cert_id().as_dangerous_comparable());

                let control = control.get(cert.cert_id().as_hex_str()).expect("control must contain cert");
                assert_eq!(control.fingerprint(), cert.fingerprint());
            }
        }
    }
}
