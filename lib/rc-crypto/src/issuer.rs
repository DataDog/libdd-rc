// Copyright 2026 Datadog, Inc
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

//! Abstract issuance of a [`Certificate`] from a [`CertificateSigningRequest`].

use std::sync::Arc;

use crate::certificate::{Certificate, csr::CertificateSigningRequest};

/// A convenience type def over an opaque error.
pub type BoxErr = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Opaque errors returned by a [`CertIssuer`].
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    /// The caller MAY retry the same request with an expectation of success.
    #[error("retryable request error: {0}")]
    Retryable(BoxErr),

    /// The caller SHOULD NOT retry the same request; it will certainly fail.
    #[error("fatal request error: {0}")]
    Fatal(BoxErr),
}

/// A [`CertIssuer`] attempts to issue a [`Certificate`] using the parameters
/// specified in the [`CertificateSigningRequest`].
pub trait CertIssuer: Send + Sync + std::fmt::Debug {
    /// Return a certificate for the provided `csr`.
    fn issue_cert_for(
        &self,
        csr: &CertificateSigningRequest,
    ) -> impl Future<Output = Result<Certificate, IssueError>> + Send;
}

impl<T> CertIssuer for Arc<T>
where
    T: CertIssuer,
{
    fn issue_cert_for(
        &self,
        csr: &CertificateSigningRequest,
    ) -> impl Future<Output = Result<Certificate, IssueError>> + Send {
        T::issue_cert_for(self, csr)
    }
}
