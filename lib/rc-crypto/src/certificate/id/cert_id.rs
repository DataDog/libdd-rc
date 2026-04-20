use smallvec::SmallVec;
use thiserror::Error;
use valuable::Valuable;
use x509_parser::prelude::{ParsedExtension, X509Certificate};

use crate::{
    cached_string_repr::CachedStringRepr, certificate::id::DangerousComparableId, hex::colon_string,
};

/// No Subject Key Identifier extension was found in the certificate.
#[derive(Debug, Error)]
#[error("no Subject Key Identifier found")]
pub struct ErrorNoSKI;

/// An opaque identifier for the [`Certificate`] this value was extracted from.
///
/// This is an untrusted value, and can be set to anything the cert issuer
/// wishes. Derived values such as a [`KeyId`] or certificate [`Fingerprint`])
/// SHOULD be preferred for general use. The
/// [`CertId::into_dangerous_comparable()`] method can be used to obtain a
/// handle that implements [`PartialEq`].
///
/// The [`CertId`] is a user friendly rename of the [Subject Key Identifier]
/// (commonly abbreviated SKI) within an X509 certificate. While the SKI claims
/// to be an identifier of the key in the cert, it does not always identify the
/// key material specifically (`hash(cert_dn + cert_serial)` is not uncommon).
///
/// [`KeyId`]: crate::keys::KeyId
/// [`Certificate`]: crate::certificate::Certificate
/// [`Fingerprint`]: crate::certificate::Fingerprint
/// [Subject Key Identifier]:
///     https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
#[derive(Debug, Hash, Clone)] // NOTE: no PartialEq - not trusted, do not compare.
pub struct CertId {
    bytes: SmallVec<[u8; 20]>,

    /// A lazily-rendered string representation of `bytes`.
    ///
    /// See [`Self::as_hex_str()`] for initialisation.
    rendered: CachedStringRepr,
}

impl CertId {
    /// Render this value following the conventions of OpenSSL's colon-delimited
    /// string representation.
    pub fn as_hex_str(&self) -> &str {
        self.rendered.get_or_init(|| colon_string(&self.bytes))
    }

    /// Return the raw bytes for this ID (private to this module).
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Obtain a wrapper type that has a [`PartialEq`] implementation, allowing
    /// this value to be compared to other values with the correctness caveats
    /// documented for this type.
    pub fn into_dangerous_comparable(self) -> DangerousComparableId<Self> {
        DangerousComparableId::from(self)
    }
}

impl From<&[u8]> for CertId {
    fn from(v: &[u8]) -> Self {
        Self {
            bytes: v.into(),
            rendered: Default::default(),
        }
    }
}

impl<'a> TryFrom<&X509Certificate<'a>> for CertId {
    type Error = ErrorNoSKI;

    fn try_from(cert: &X509Certificate<'a>) -> Result<Self, Self::Error> {
        cert.iter_extensions()
            .find_map(|v| match v.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(ski) => Some(ski.0),
                _ => None,
            })
            .ok_or(ErrorNoSKI)
            .map(CertId::from)
    }
}

impl Valuable for CertId {
    fn as_value(&self) -> valuable::Value<'_> {
        valuable::Value::String(self.as_hex_str())
    }

    fn visit(&self, visit: &mut dyn valuable::Visit) {
        visit.visit_value(self.as_value());
    }
}

#[cfg(test)]
mod tests {
    use static_assertions::assert_not_impl_any;
    use x509_parser::prelude::FromDer;

    use super::*;

    use crate::{certificate::tests::cert_fixture, valuable_assert::assert_valuable_repr};

    const FIXTURE_SKI_STR: &str = "dc:8d:b6:27:52:78:58:4c:fd:a2:43:db:cb:2b:e0:57:68:6e:2b:8e";

    // Why: a CertId can be set to anything by the issuer, making it unreliable
    // as a unique identifier, and should not be used to compare two
    // certificates for equality (outside of chain building which is then
    // cryptographically verified).
    assert_not_impl_any!(CertId: PartialEq, Eq);

    fn fixture_ski() -> CertId {
        let der = cert_fixture().as_der();
        let cert = X509Certificate::from_der(&der).expect("valid DER").1;

        CertId::try_from(&cert).expect("extract SKI")
    }

    #[test]
    fn test_fixture() {
        let aki = fixture_ski();

        assert_eq!(aki.as_hex_str(), FIXTURE_SKI_STR,);
    }

    #[test]
    fn test_valuable_repr() {
        let aki = fixture_ski();

        assert_valuable_repr(&aki, FIXTURE_SKI_STR);
    }
}
