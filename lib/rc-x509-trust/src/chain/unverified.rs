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

use rc_crypto::certificate::Certificate;
use valuable::Valuable;

/// An unverified candidate chain for some leaf [`Certificate`]. to some root.
///
/// This type contains the chain of intermediates only.
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
/// Where `<leaf>` and `<root>` are implicit / not retained within the
/// [`UntrustedChain`] and must be provided alongside it for any trust
/// operations.
#[derive(Debug)]
pub(crate) struct UntrustedChain(Vec<Arc<Certificate>>);

impl UntrustedChain {
    /// Borrow the chain content.
    pub(crate) fn as_slice(&self) -> &[Arc<Certificate>] {
        &self.0
    }
}

impl From<Vec<Arc<Certificate>>> for UntrustedChain {
    fn from(value: Vec<Arc<Certificate>>) -> Self {
        Self(value)
    }
}

impl Valuable for UntrustedChain {
    fn as_value(&self) -> valuable::Value<'_> {
        valuable::Value::Listable(&self.0)
    }

    fn visit(&self, visit: &mut dyn valuable::Visit) {
        for v in &self.0 {
            v.visit(visit)
        }
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

        let chain = UntrustedChain::from(vec![
            Arc::new(int_a.cert().clone()),
            Arc::new(int_b.cert().clone()),
        ]);

        assert_valuable_repr(
            &chain,
            format!(
                "\
- serial_number:
    {cert_a_serial}
- fingerprint:
    {cert_a_fingerprint}
- validity:
    {cert_a_validity}
- serial_number:
    {cert_b_serial}
- fingerprint:
    {cert_b_fingerprint}
- validity:
    {cert_b_validity}
",
                cert_a_serial = int_a.cert().serial_number().as_hex_str(),
                cert_a_fingerprint = int_a.cert().fingerprint().as_hex_str(),
                cert_a_validity = int_a.cert().validity(),
                cert_b_serial = int_b.cert().serial_number().as_hex_str(),
                cert_b_fingerprint = int_b.cert().fingerprint().as_hex_str(),
                cert_b_validity = int_b.cert().validity(),
            )
            .as_str(),
        );
    }
}
