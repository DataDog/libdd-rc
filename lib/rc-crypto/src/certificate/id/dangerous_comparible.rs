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

use std::{borrow::Cow, fmt::Debug};

use equivalent::Equivalent;

use crate::certificate::id::{CertId, IssuerCertId};

/// A wrapper over `T` that allows making equality comparisons against values
/// that have high risk of correctness issues (e.g. easily forged).
#[derive(Hash, Clone)]
pub struct DangerousComparableId<'a, T>(Cow<'a, T>)
where
    T: ToOwned + ?Sized + 'a;

impl<'a, T> Debug for DangerousComparableId<'a, T>
where
    T: Debug + ToOwned,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DangerousComparableId")
            .field(self.0.as_ref())
            .finish()
    }
}

impl<'a, T> DangerousComparableId<'a, T>
where
    T: ToOwned + ?Sized + 'static,
{
    /// Consume this value, cloning the inner data if borrowed, and return an
    /// owned `DangerousComparableId<'static, T>`.
    pub fn into_owned(self) -> DangerousComparableId<'static, T> {
        DangerousComparableId(Cow::Owned(self.0.into_owned()))
    }
}

impl<'a, T> Eq for DangerousComparableId<'a, T>
where
    DangerousComparableId<'a, T>: PartialEq,
    T: ToOwned,
{
}

///// CertId impls

impl<'a> DangerousComparableId<'a, CertId> {
    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<'a> From<CertId> for DangerousComparableId<'a, CertId> {
    fn from(value: CertId) -> Self {
        Self(Cow::Owned(value))
    }
}

impl<'a> From<&'a CertId> for DangerousComparableId<'a, CertId> {
    fn from(value: &'a CertId) -> Self {
        Self(Cow::Borrowed(value))
    }
}

impl<'a> PartialEq for DangerousComparableId<'a, CertId> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl<'a> PartialEq<DangerousComparableId<'a, CertId>> for DangerousComparableId<'a, IssuerCertId> {
    fn eq(&self, other: &DangerousComparableId<'a, CertId>) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl<'a> PartialEq<CertId> for DangerousComparableId<'a, CertId> {
    fn eq(&self, other: &CertId) -> bool {
        self.0.as_bytes() == other.as_bytes()
    }
}

impl<'a> PartialEq<IssuerCertId> for DangerousComparableId<'a, CertId> {
    fn eq(&self, other: &IssuerCertId) -> bool {
        self.0.as_bytes() == other.as_bytes()
    }
}

impl Equivalent<DangerousComparableId<'static, CertId>> for CertId {
    fn equivalent(&self, key: &DangerousComparableId<'static, CertId>) -> bool {
        key == self
    }
}

///// IssuerCertId impls

impl<'a> DangerousComparableId<'a, IssuerCertId> {
    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<'a> From<IssuerCertId> for DangerousComparableId<'a, IssuerCertId> {
    fn from(value: IssuerCertId) -> Self {
        Self(Cow::Owned(value))
    }
}

impl<'a> From<&'a IssuerCertId> for DangerousComparableId<'a, IssuerCertId> {
    fn from(value: &'a IssuerCertId) -> Self {
        Self(Cow::Borrowed(value))
    }
}

impl<'a> PartialEq for DangerousComparableId<'a, IssuerCertId> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl<'a> PartialEq<DangerousComparableId<'a, IssuerCertId>> for DangerousComparableId<'a, CertId> {
    fn eq(&self, other: &DangerousComparableId<'a, IssuerCertId>) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl<'a> PartialEq<CertId> for DangerousComparableId<'a, IssuerCertId> {
    fn eq(&self, other: &CertId) -> bool {
        self.0.as_bytes() == other.as_bytes()
    }
}

impl<'a> PartialEq<IssuerCertId> for DangerousComparableId<'a, IssuerCertId> {
    fn eq(&self, other: &IssuerCertId) -> bool {
        self.0.as_bytes() == other.as_bytes()
    }
}

impl Equivalent<DangerousComparableId<'static, IssuerCertId>> for IssuerCertId {
    fn equivalent(&self, key: &DangerousComparableId<'static, IssuerCertId>) -> bool {
        key == self
    }
}
