use thiserror::Error;
use valuable::Valuable;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::X509Certificate;

use crate::certificate::id::{CertId, DangerousComparableId};

/// No Authority Key Identifier extension was found in the certificate.
#[derive(Debug, Error)]
#[error("no Authority Key Identifier found")]
pub struct ErrorNoAKI;

/// An opaque identifier that describes the [`Certificate`] of the issuer (CA)
/// that issued the [`Certificate`] this value was extracted from.
///
/// This is an untrusted value, and can be set to anything the cert issuer
/// wishes. Derived values such as a [`KeyId`] or certificate [`Fingerprint`])
/// SHOULD be preferred for general use. The
/// [`IssuerCertId::into_dangerous_comparable()`] method can be used to obtain a
/// handle that implements [`PartialEq`].
///
/// The [`IssuerCertId`] is a user friendly rename of the [Authority Key
/// Identifier] (commonly abbreviated AKI) within an X509 certificate. While the
/// AKI claims to be an identifier of the key in the cert, it does not always
/// identify the key material specifically (`hash(cert_dn + cert_serial)` is not
/// uncommon).
///
/// [`KeyId`]: crate::keys::KeyId
/// [`Certificate`]: crate::certificate::Certificate
/// [`Fingerprint`]: crate::certificate::Fingerprint
/// [Authority Key Identifier]:
///     https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1
#[derive(Debug, Hash, Clone)] // NOTE: no PartialEq - not trusted, do not compare.
pub struct IssuerCertId(CertId);

impl IssuerCertId {
    /// Render this value following the conventions of OpenSSL's colon-delimited
    /// string representation.
    pub fn as_hex_str(&self) -> &str {
        self.0.as_hex_str()
    }

    /// Return the raw bytes for this ID (private to this module).
    pub(super) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Obtain a wrapper type that has a [`PartialEq`] implementation, allowing
    /// this value to be compared to other values with the correctness caveats
    /// documented for this type.
    pub fn into_dangerous_comparable(self) -> DangerousComparableId<Self> {
        DangerousComparableId::from(self)
    }
}

impl Valuable for IssuerCertId {
    fn as_value(&self) -> valuable::Value<'_> {
        self.0.as_value()
    }

    fn visit(&self, visit: &mut dyn valuable::Visit) {
        self.0.visit(visit);
    }
}

impl From<&[u8]> for IssuerCertId {
    fn from(v: &[u8]) -> Self {
        Self(CertId::from(v))
    }
}

impl<'a> TryFrom<&X509Certificate<'a>> for IssuerCertId {
    type Error = ErrorNoAKI;

    fn try_from(cert: &X509Certificate<'a>) -> Result<Self, Self::Error> {
        cert.iter_extensions()
            .find_map(|v| match v.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    aki.key_identifier.as_ref().map(|kid| kid.0)
                }
                _ => None,
            })
            .ok_or(ErrorNoAKI)
            .map(CertId::from)
            .map(Self)
    }
}

#[cfg(test)]
mod tests {
    use static_assertions::assert_not_impl_any;
    use x509_parser::prelude::FromDer as _;

    use super::*;

    use crate::{certificate::tests::cert_fixture, valuable_assert::assert_valuable_repr};

    const FIXTURE_AKI_STR: &str = "20:6c:8e:cf:e4:21:a7:ff:ed:23:c8:3d:37:0f:77:81:84:71:0e:15";

    // Why: an IssuerCertId can be set to anything by the issuer, making it
    // unreliable as a unique identifier, and should not be used to compare two
    // certificates for equality (outside of chain building which is then
    // cryptographically verified).
    assert_not_impl_any!(IssuerCertId: PartialEq, Eq);

    fn fixture_aki() -> IssuerCertId {
        let der = cert_fixture().as_der();
        let cert = X509Certificate::from_der(&der).expect("valid DER").1;

        IssuerCertId::try_from(&cert).expect("extract AKI")
    }

    #[test]
    fn test_fixture() {
        let aki = fixture_aki();

        assert_eq!(aki.as_hex_str(), FIXTURE_AKI_STR,);
    }

    #[test]
    fn test_valuable_repr() {
        let aki = fixture_aki();

        assert_valuable_repr(&aki, FIXTURE_AKI_STR);
    }
}
