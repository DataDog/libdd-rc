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

use rc_crypto::{certificate::csr::CertificateSigningRequest, keys::PrivateKey};
use rcgen::{BasicConstraints, GeneralSubtree, IsCa, NameConstraints};

use crate::test_issuer::{
    CertBuilder, Identity,
    cert_builder::{TestCertTemplate, sign_tbs},
};

/// An initialisation template for an intermediate CA certificate.
#[derive(Debug)]
pub(crate) struct IntermediateTemplate<'a> {
    parent: &'a Identity,
    allowed_domain: Option<String>,
    path_len: Option<u8>,
}

impl<'a> TestCertTemplate for IntermediateTemplate<'a> {
    fn build(self, cn: String, key: PrivateKey) -> Identity {
        let csr = CertificateSigningRequest::new_intermediate(&key, &cn).expect("invalid CSR");

        let mut tbs = rcgen::CertificateSigningRequestParams::from_pem(&csr.as_pem_string())
            .expect("invalid TBS");

        tbs.params.is_ca = match self.path_len {
            Some(v) => IsCa::Ca(BasicConstraints::Constrained(v)),
            None => IsCa::Ca(BasicConstraints::Unconstrained),
        };

        if let Some(allowed) = self.allowed_domain {
            tbs.params.name_constraints = Some(NameConstraints {
                permitted_subtrees: vec![GeneralSubtree::DnsName(allowed)],
                excluded_subtrees: vec![],
            });
        }

        sign_tbs(self.parent, key, tbs)
    }
}

impl<'a> CertBuilder<IntermediateTemplate<'a>> {
    /// Initialise a new intermediate CA template.
    pub(crate) fn new_intermediate(cn: impl Into<String>, parent: &'a Identity) -> Self {
        CertBuilder {
            cn: cn.into(),
            role: IntermediateTemplate {
                parent,
                allowed_domain: None,
                path_len: None,
            },
        }
    }

    /// Set the permitted NameConstraint domains (required).
    pub(crate) fn allowed_domain(mut self, domain: impl Into<String>) -> Self {
        self.role.allowed_domain = Some(domain.into());
        self
    }

    /// Set the pathLen constraint for the basic constraint CA field (default:
    /// 0).
    pub(crate) fn path_len(mut self, n: u8) -> Self {
        self.role.path_len = Some(n);
        self
    }
}
