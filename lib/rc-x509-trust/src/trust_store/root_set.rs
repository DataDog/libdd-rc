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

use rc_crypto::certificate::id::{DangerousComparableId, IssuerCertId};
use rc_x509_roots::RootCertificate;

/// A set of one or more [`RootCertificate`] with helper methods.
#[derive(Debug, Clone)]
pub(crate) struct RootSet<const N: usize> {
    roots: [RootCertificate; N],
}

impl<const N: usize> RootSet<N> {
    /// Construct a new [`RootSet`] from the provided set of
    /// [`RootCertificate`].
    pub(crate) fn new(roots: [RootCertificate; N]) -> Self {
        Self { roots }
    }

    /// Returns true if this [`RootSet`] contains a root with an
    /// [`IssuerCertId`] matching the search `needle`.
    pub(crate) fn contains(&self, needle: DangerousComparableId<IssuerCertId>) -> bool {
        self.roots
            .iter()
            .any(|v| v.cert_id().as_dangerous_comparable() == needle)
    }

    /// Unwrap this [`RootSet`] into the underlying array.
    pub(crate) fn into_array(self) -> [RootCertificate; N] {
        self.roots
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use crate::test_issuer::TestCA;

    use super::*;

    /// Generate a randomly ordered [`RootSet`] - useful to assert that both
    /// provided root certificates are honoured.
    pub(crate) fn arbitrary_ordered_root_set(
        ca1: &TestCA,
        ca2: &TestCA,
    ) -> impl Strategy<Value = RootSet<2>> {
        Just([ca1.root_cert(), ca2.root_cert()])
            .prop_shuffle()
            .prop_map(RootSet::new)
    }
}
