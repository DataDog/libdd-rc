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

//! An abstract method of obtaining a signature.

use std::sync::Arc;

use crate::{Signature, keys::PublicKey};

/// A [`Signer`] provides the ability to generate a [`Signature`] for provided
/// payload data.
///
/// This abstraction decouples the caller from the underlying key type and
/// storage.
///
/// Note that the key material used by a [`Signer`] instance MUST NOT change for
/// the lifetime of the [`Signer`] instance.
pub trait Signer: std::fmt::Debug + Send + Sync {
    /// Sign `data` with this private key.
    ///
    /// Signatures are non-deterministic and rely on randomness on the host.
    fn sign(&self, data: &[u8]) -> Signature;

    /// Obtain the [`PublicKey`] for this [`Signer`].
    ///
    /// Invariant: from the caller's perspective, a single [`Signer`] instance
    /// always returns the same [`PublicKey`] (key material).
    fn public_key(&self) -> PublicKey<'_>;
}

impl<T> Signer for Arc<T>
where
    T: Signer,
{
    fn sign(&self, data: &[u8]) -> Signature {
        T::sign(self, data)
    }

    fn public_key(&self) -> PublicKey<'_> {
        T::public_key(self)
    }
}
