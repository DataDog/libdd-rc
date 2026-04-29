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

use bytes::Bytes;
use rc_crypto::certificate::{Certificate, Fingerprint, InvalidDer};

/// An [`UntrustedCert`] is a [`Certificate`] that has been received from the RC
/// delivery server, but not yet verified by the client to chain to the root.
///
/// A [`Certificate`] can be obtained from an [`UntrustedCert`] by validating it
/// chains to the root certificate.
#[derive(Debug)]
pub struct UntrustedCert(Certificate);

impl PartialEq for UntrustedCert {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint() == other.fingerprint()
    }
}

impl UntrustedCert {
    /// Parse an [`UntrustedCert`] from DER bytes obtained from an untrusted
    /// source.
    pub fn from_der(der: impl Into<Bytes>) -> Result<Self, InvalidDer> {
        Certificate::from_der(der).map(Self)
    }

    /// Return the (unforgeable) [`Fingerprint`] that uniquely identifies the
    /// underlying [`Certificate`].
    pub fn fingerprint(&self) -> &Fingerprint {
        self.0.fingerprint()
    }

    /// Access the inner [`Certificate`].
    pub(crate) fn as_trusted(&self) -> &Certificate {
        &self.0
    }
}

impl From<Certificate> for UntrustedCert {
    fn from(value: Certificate) -> Self {
        Self(value)
    }
}
