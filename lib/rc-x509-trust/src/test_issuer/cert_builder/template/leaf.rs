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

use rc_crypto::certificate::csr::CertificateSigningRequest;
use rcgen::{IsCa, SanType, string::Ia5String};

use crate::test_issuer::{
    CertBuilder, Identity,
    cert_builder::{Params, TestCertTemplate},
};

/// An initialisation template for a leaf signer certificate.
#[derive(Debug)]
pub(crate) struct LeafTemplate<'a> {
    parent: &'a Identity,
    sans: Vec<String>,
}

impl<'a> TestCertTemplate for LeafTemplate<'a> {
    fn build(self, params: Params) -> Identity {
        assert!(!self.sans.is_empty(), "no san provided for leaf cert");

        let csr = CertificateSigningRequest::new_leaf(&params.key, &params.cn, &self.sans[0])
            .expect("invalid CSR");

        let mut tbs = rcgen::CertificateSigningRequestParams::from_pem(&csr.as_pem_string())
            .expect("invalid TBS");

        tbs.params.is_ca = IsCa::ExplicitNoCa;

        // Override SANs with the full list (the CSR only accepts one).
        tbs.params.subject_alt_names = self
            .sans
            .into_iter()
            .map(|s| SanType::DnsName(Ia5String::try_from(s).expect("invalid SAN")))
            .collect();

        params.sign(tbs.params, self.parent)
    }
}

impl<'a> CertBuilder<LeafTemplate<'a>> {
    /// Initialise a new leaf signer certificate template.
    pub(crate) fn new_leaf(cn: impl Into<String>, parent: &'a Identity) -> Self {
        CertBuilder::new(
            cn,
            LeafTemplate {
                parent,
                sans: vec![],
            },
        )
    }

    /// Set the dNSName SAN values for this leaf certificate (at least one is
    /// required).
    pub(crate) fn with_sans(
        &mut self,
        sans: impl IntoIterator<Item = impl Into<String>>,
    ) -> &mut Self {
        self.template.sans = sans.into_iter().map(Into::into).collect();
        self
    }

    /// Set the SAN domain for this signer cert (required).
    pub(crate) fn san(mut self, sans: impl Into<String>) -> Self {
        self.with_sans([sans]);
        self
    }
}
