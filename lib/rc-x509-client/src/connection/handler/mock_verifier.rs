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

use std::{collections::VecDeque, sync::Mutex};

use rc_crypto::certificate::id::CertId;
use rc_x509_trust::trust_store::VerificationError;

use crate::{Payload, ProdSealed, connection::AttestationVerifier};

#[derive(Debug, Default)]
struct Inner {
    verify_ret: VecDeque<Result<(), VerificationError>>,
}

#[derive(Debug, Default)]
pub(crate) struct MockVerifier(Mutex<Inner>);

impl MockVerifier {
    pub(crate) fn with_verify_ret(
        self,
        v: impl IntoIterator<Item = Result<(), VerificationError>>,
    ) -> Self {
        self.0.lock().unwrap().verify_ret = v.into_iter().collect();
        self
    }
}

impl AttestationVerifier for MockVerifier {
    fn verify(
        &self,
        _signing_cert_id: &CertId,
        _signature: &rc_crypto::Signature,
        _payload: &Payload,
        _endpoint: &rc_x509_trust::EndpointHostname,
    ) -> Result<(), VerificationError> {
        self.0
            .lock()
            .unwrap()
            .verify_ret
            .pop_front()
            .expect("no mock values configured for verify()")
    }

    fn add<U>(&self, _certs: U)
    where
        U: Iterator<Item = rc_x509_trust::cert::UntrustedCert>,
    {
        // It does nothing!
    }
}

impl ProdSealed for MockVerifier {}
