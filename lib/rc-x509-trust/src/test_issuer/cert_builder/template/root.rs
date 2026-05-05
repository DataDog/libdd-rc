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

use rc_crypto::certificate::Certificate;
use rcgen::IsCa;

use crate::test_issuer::{
    CertBuilder, Identity,
    cert_builder::{Params, TestCertTemplate, generate_ski, serial_number},
};

/// An initialisation template for a self-signed certificate (typically a root).
#[derive(Debug, Default)]
pub(crate) struct SelfSignedTemplate;

impl TestCertTemplate for SelfSignedTemplate {
    fn build(self, params: Params) -> Identity {
        let mut tbs =
            rcgen::CertificateParams::new(&[params.cn]).expect("invalid self-signed cert params");

        // This has to be duplicated because it differs from every other
        // template in that there is no parent to sign with.

        tbs.serial_number = Some(serial_number());
        tbs.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        tbs.use_authority_key_identifier_extension = true;
        tbs.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(
            params.cert_id.unwrap_or_else(|| generate_ski(&params.key)),
        );

        let issuer = rcgen::CertifiedIssuer::self_signed(tbs.clone(), params.key)
            .expect("invalid self-signed issuer");
        let cert =
            Certificate::from_pem(issuer.pem().as_bytes()).expect("valid cert for test issuer");

        Identity::new(cert, issuer)
    }
}

impl CertBuilder<SelfSignedTemplate> {
    /// Obtain a self-signed certificate.
    pub(crate) fn new_root(cn: impl Into<String>) -> Self {
        CertBuilder::new(cn, SelfSignedTemplate::default())
    }
}
