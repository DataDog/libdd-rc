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

use rc_crypto::certificate::{Certificate, id::CertId};

/// A [`CertCache`] holds [`Certificate`] instances locally, making them
/// available for retrieval and removal by their [`CertId`].
///
/// # Panics
///
/// Implementations guarantee a stable mapping of [`CertId`] to [`Certificate`],
/// panicking if any inconsistent mapping is found under the assumption exactly
/// one [`Certificate`] exists per key.
pub trait CertCache: Send + Sync + std::fmt::Debug + 'static {
    /// Insert `cert`, making it available to subsequent queries using its
    /// [`CertId`].
    fn insert(&mut self, cert: Certificate);

    /// Retrieve a [`Certificate`] by the [`CertId`], if previously inserted.
    fn get(&self, cert_id: &CertId) -> Option<Arc<Certificate>>;

    /// Remove the [`Certificate`] which has the specified [`CertId`], returning
    /// true on success, or false if there is not matching [`Certificate`]
    /// stored.
    fn remove(&mut self, cert_id: &CertId) -> bool;
}
