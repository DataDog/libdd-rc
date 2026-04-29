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

use std::sync::{Arc, LazyLock};

use crate::{
    cert::RootCertificate,
    test_issuer::{CertBuilder, Identity},
};

#[allow(clippy::test_attr_in_doctest)] // Not a test that needs running.
/// A "Certificate Authority" for testing:
///
/// ```rust
/// use crate::test_issuer::*;
///
/// static CA: TestCA = TestCA::new();
///
/// // tests here!
/// #[test]
/// fn test_something_with_a_root() {
///    let leaf = CertBuilder::new_leaf("Banana Signer Cert", CA.root())
///        .san("us1.example.com")
///        .build();
/// }
/// ```
///
#[derive(Debug)]
pub(crate) struct TestCA {
    root: LazyLock<Arc<Identity>>,
}

impl Default for TestCA {
    fn default() -> Self {
        Self::new()
    }
}

impl TestCA {
    /// Initialise a CA with a new random root.
    pub(crate) const fn new() -> Self {
        Self {
            root: LazyLock::new(|| Arc::new(CertBuilder::new_root("Banana Test CA").build())),
        }
    }

    /// Return the root of trust signer [`Identity`].
    pub(crate) fn root(&self) -> &Arc<Identity> {
        &self.root
    }

    /// Obtain the typed [`RootCertificate`] for this CA.
    ///
    /// This is helper and is semantically identical to constructing a
    /// [`RootCertificate`] from the `CA.root().cert()`.
    pub(crate) fn root_cert(&self) -> RootCertificate {
        RootCertificate::from_trusted_cert(self.root.cert().clone())
    }
}
