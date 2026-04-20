use crate::certificate::id::{CertId, IssuerCertId};

/// A wrapper over `T` that allows making equality comparisons against values
/// that have high risk of correctness issues (e.g. easily forged).
#[derive(Debug, Hash, Clone)]
pub struct DangerousComparableId<T>(T);

impl<T> AsRef<T> for DangerousComparableId<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

/////

impl From<CertId> for DangerousComparableId<CertId> {
    fn from(value: CertId) -> Self {
        Self(value)
    }
}

impl PartialEq for DangerousComparableId<CertId> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl PartialEq<DangerousComparableId<CertId>> for DangerousComparableId<IssuerCertId> {
    fn eq(&self, other: &DangerousComparableId<CertId>) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl PartialEq<CertId> for DangerousComparableId<CertId> {
    fn eq(&self, other: &CertId) -> bool {
        self.0.as_bytes() == other.as_bytes()
    }
}

/////

impl From<IssuerCertId> for DangerousComparableId<IssuerCertId> {
    fn from(value: IssuerCertId) -> Self {
        Self(value)
    }
}

impl PartialEq for DangerousComparableId<IssuerCertId> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl PartialEq<DangerousComparableId<IssuerCertId>> for DangerousComparableId<CertId> {
    fn eq(&self, other: &DangerousComparableId<IssuerCertId>) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl PartialEq<IssuerCertId> for DangerousComparableId<IssuerCertId> {
    fn eq(&self, other: &IssuerCertId) -> bool {
        self.0.as_bytes() == other.as_bytes()
    }
}

impl<T> Eq for DangerousComparableId<T> where DangerousComparableId<T>: PartialEq {}
