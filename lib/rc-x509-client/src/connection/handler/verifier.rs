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

use rc_crypto::{Signature, certificate::id::CertId};
use rc_x509_trust::trust_store::{TrustStore, VerificationError};
use tokio_util::bytes::Bytes;

/// An abstract verifier of payload signatures.
///
/// Implementations must return [`Ok`] iff `signature` is a valid cryptographic
/// proof attesting the integrity and provenance of `payload`, and can be proven
/// to have been signed by `signing_cert_id`, which MUST chain to a explicitly
/// trusted root.
pub trait AttestationVerifier: std::fmt::Debug + Send + Sync {
    /// Returns [`Ok`] iff this `payload` can be cryptographically proven to
    /// have been signed by `signing_cert_id`, and which chains to an explicitly
    /// trusted root.
    fn validate(
        &self,
        signing_cert_id: CertId,
        signature: Signature,
        payload: Bytes,
    ) -> Result<(), VerificationError>;
}

impl<T> AttestationVerifier for Arc<T>
where
    T: AttestationVerifier,
{
    fn validate(
        &self,
        signing_cert_id: CertId,
        signature: Signature,
        payload: Bytes,
    ) -> Result<(), VerificationError> {
        T::validate(self, signing_cert_id, signature, payload)
    }
}

/// Allow using a [`TrustStore`] to verify signatures.
impl<const N: usize, T> AttestationVerifier for TrustStore<N, T>
where
    T: rc_x509_trust::trust_store::CertCache,
{
    fn validate(
        &self,
        signing_cert_id: CertId,
        signature: Signature,
        payload: Bytes,
    ) -> Result<(), VerificationError> {
        TrustStore::validate(self, signing_cert_id, signature, payload)
    }
}
