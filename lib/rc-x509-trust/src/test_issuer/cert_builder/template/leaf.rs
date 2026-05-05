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
use rcgen::IsCa;

use crate::test_issuer::{
    CertBuilder, Identity,
    cert_builder::{Params, TestCertTemplate},
};

/// An initialisation template for a leaf signer certificate.
#[derive(Debug)]
pub(crate) struct LeafTemplate<'a> {
    parent: &'a Identity,
    san: Option<String>,
}

impl<'a> TestCertTemplate for LeafTemplate<'a> {
    fn build(self, params: Params) -> Identity {
        let csr = CertificateSigningRequest::new_leaf(
            &params.key,
            &params.cn,
            self.san.as_ref().expect("no san provided for leaf cert"),
        )
        .expect("invalid CSR");

        let mut tbs = rcgen::CertificateSigningRequestParams::from_pem(&csr.as_pem_string())
            .expect("invalid TBS");

        tbs.params.is_ca = IsCa::ExplicitNoCa;

        params.sign(tbs.params, self.parent)
    }
}

impl<'a> CertBuilder<LeafTemplate<'a>> {
    /// Initialise a new leaf signer certificate template.
    pub(crate) fn new_leaf(cn: impl Into<String>, parent: &'a Identity) -> Self {
        CertBuilder::new(cn, LeafTemplate { parent, san: None })
    }

    /// Set the SAN domain for this signer cert (required).
    pub(crate) fn san(mut self, san: impl Into<String>) -> Self {
        self.template.san = Some(san.into());
        self
    }
}
