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

use rc_crypto::{certificate::Certificate, keys::PrivateKey};
use rcgen::{CertificateParams, CertifiedIssuer};

use crate::test_issuer::Identity;

/// A CSR [`Template`] containing role-specific fields necessary to create a CSR
/// for the implementing type.
pub(crate) trait TestCertTemplate: std::fmt::Debug + Sized {
    fn build(self, params: Params) -> Identity;
}

#[derive(Debug)]
pub(crate) struct Params {
    pub(super) key: PrivateKey,

    /// Fields common to all templates.
    pub(super) cn: String,

    /// Override for the SKI field value.
    pub(super) cert_id: Option<Vec<u8>>,
}

impl Params {
    pub(super) fn sign(self, mut tbs: CertificateParams, parent: &Identity) -> Identity {
        //
        // NOTE: config duplicated for root template.
        //

        tbs.serial_number = Some(serial_number());
        tbs.use_authority_key_identifier_extension = true;
        tbs.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(
            self.cert_id.unwrap_or_else(|| generate_ski(&self.key)),
        );

        let issuer =
            CertifiedIssuer::signed_by(tbs, self.key, parent.issuer()).expect("signed cert");

        let cert = Certificate::from_der(issuer.der().to_vec()).expect("valid DER");

        Identity::new(cert, issuer)
    }
}

/// A helper to construct certificates for tests.
#[derive(Debug)]
pub(crate) struct CertBuilder<T> {
    params: Params,

    /// The template type, holding template-specific fields.
    pub(super) template: T,
}

impl<T> CertBuilder<T>
where
    T: TestCertTemplate,
{
    pub(super) fn new(cn: impl Into<String>, template: T) -> Self {
        Self {
            params: Params {
                cn: cn.into(),
                key: PrivateKey::new(),
                cert_id: None,
            },
            template,
        }
    }

    /// Obtain the [`Identity`] for the configured certificate template.
    pub(crate) fn build(self) -> Identity {
        self.template.build(self.params)
    }

    /// Override the cert ID / SKI value specified in the final certificate.
    pub(crate) fn set_cert_id(mut self, id: impl Into<Vec<u8>>) -> Self {
        self.params.cert_id = Some(id.into());
        self
    }
}

/// Always returns the same serial number, proving the test under code does not
/// distinguish certificates by their serial numbers.
pub(super) fn serial_number() -> rcgen::SerialNumber {
    rcgen::SerialNumber::from_slice(&[42])
}

// This crate treats AKI and SKI as opaque values, not as trusted derivates of
// the keys or certs.
//
// In order to concretely assert this behaviour, modify the SKI such that it is
// not equal to the KeyId.
pub(super) fn generate_ski(key: &PrivateKey) -> Vec<u8> {
    let mut ski = key.public_key().key_id().to_vec();
    ski.reverse();
    ski.push(42);
    ski
}
