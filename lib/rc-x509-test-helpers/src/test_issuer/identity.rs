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

use rc_crypto::{Signature, Signer, certificate::Certificate, keys::PrivateKey};

/// An [`Identity`] is a [`Certificate`] and the signing key for it.
#[derive(Debug)]
pub struct Identity {
    cert: Certificate,
    issuer: rcgen::CertifiedIssuer<'static, PrivateKey>,
}

impl Identity {
    pub(crate) fn new(
        cert: Certificate,
        issuer: rcgen::CertifiedIssuer<'static, PrivateKey>,
    ) -> Self {
        Self { cert, issuer }
    }

    pub fn key(&self) -> &PrivateKey {
        self.issuer.key()
    }

    pub fn cert(&self) -> &Certificate {
        &self.cert
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        self.issuer().key().sign(data)
    }

    pub(crate) fn issuer(&self) -> &rcgen::CertifiedIssuer<'static, PrivateKey> {
        &self.issuer
    }
}
