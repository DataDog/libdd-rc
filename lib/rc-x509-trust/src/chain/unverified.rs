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

use std::sync::Arc;

use crate::cert::UntrustedCert;
use rc_x509_roots::RootCertificate;
use valuable::{Listable, Valuable};

/// An unverified candidate chain for some leaf [`Certificate`], to the included
/// root.
///
/// This type contains the chain of intermediates and root only - the leaf is
/// implicit.
///
/// An [`UntrustedChain`] is not yet cryptographically verified and must not be
/// trusted.
///
/// ## Chain Value
///
/// This type holds a partial path from a leaf [`Certificate`] to a root, but
/// includes neither:
///
/// ```text
///                 <leaf> -> [SubCA 2, SubCA 1] -> <root>
/// ```
///
/// Where `<leaf>` is implicit / not retained within the [`UntrustedChain`] and
/// must be provided alongside it for any trust operations.
#[derive(Debug)]
pub(crate) struct UntrustedChain<'a>(&'a RootCertificate, Vec<Arc<UntrustedCert>>);

impl<'a> UntrustedChain<'a> {
    pub(crate) fn new(root: &'a RootCertificate, intermediates: Vec<Arc<UntrustedCert>>) -> Self {
        Self(root, intermediates)
    }

    /// Borrow the chain content.
    pub(crate) fn as_slice(&self) -> &[Arc<UntrustedCert>] {
        &self.1
    }
}

impl<'a> Valuable for UntrustedChain<'a> {
    fn as_value(&self) -> valuable::Value<'_> {
        valuable::Value::Listable(self)
    }

    fn visit(&self, visit: &mut dyn valuable::Visit) {
        self.0.visit(visit);

        for v in &self.1 {
            v.visit(visit)
        }
    }
}

impl<'a> Listable for UntrustedChain<'a> {
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.1.len() + 1;
        (n, Some(n))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rc_x509_test_helpers::assert_valuable_repr;

    use crate::test_issuer::{CertBuilder, TestCA};

    use super::*;

    static CA: TestCA = TestCA::new();

    #[test]
    fn test_valuable_repr() {
        let int_a = CertBuilder::new_intermediate("A", CA.root()).build();
        let int_b = CertBuilder::new_intermediate("B", &int_a).build();

        let root_cert = CA.root_cert();
        let chain = UntrustedChain::new(
            &root_cert,
            vec![
                Arc::new(UntrustedCert::from(int_a.cert().clone())),
                Arc::new(UntrustedCert::from(int_b.cert().clone())),
            ],
        );

        assert_valuable_repr(
            &chain,
            format!(
                "\
- serial_number:
    {root_serial}
- fingerprint:
    {root_fingerprint}
- validity:
    {root_validity}
- cert_id:
    {root_cert_id}
- issuer_cert_id:
    {root_issuer_cert_id}
- is_ca:
    {root_is_ca}
- serial_number:
    {cert_a_serial}
- fingerprint:
    {cert_a_fingerprint}
- validity:
    {cert_a_validity}
- cert_id:
    {cert_a_cert_id}
- issuer_cert_id:
    {cert_a_issuer_cert_id}
- is_ca:
    {cert_a_is_ca}
- serial_number:
    {cert_b_serial}
- fingerprint:
    {cert_b_fingerprint}
- validity:
    {cert_b_validity}
- cert_id:
    {cert_b_cert_id}
- issuer_cert_id:
    {cert_b_issuer_cert_id}
- is_ca:
    {cert_b_is_ca}
",
                root_serial = CA.root().cert().serial_number().as_hex_str(),
                root_fingerprint = CA.root().cert().fingerprint().as_hex_str(),
                root_validity = CA.root().cert().validity(),
                root_cert_id = CA.root().cert().cert_id(),
                root_issuer_cert_id = CA.root().cert().issuer_cert_id(),
                root_is_ca = CA.root().cert().is_ca(),
                cert_a_serial = int_a.cert().serial_number().as_hex_str(),
                cert_a_fingerprint = int_a.cert().fingerprint().as_hex_str(),
                cert_a_validity = int_a.cert().validity(),
                cert_a_cert_id = int_a.cert().cert_id(),
                cert_a_issuer_cert_id = int_a.cert().issuer_cert_id(),
                cert_a_is_ca = int_a.cert().is_ca(),
                cert_b_serial = int_b.cert().serial_number().as_hex_str(),
                cert_b_fingerprint = int_b.cert().fingerprint().as_hex_str(),
                cert_b_validity = int_b.cert().validity(),
                cert_b_cert_id = int_b.cert().cert_id(),
                cert_b_issuer_cert_id = int_b.cert().issuer_cert_id(),
                cert_b_is_ca = int_b.cert().is_ca(),
            )
            .as_str(),
        );
    }
}
