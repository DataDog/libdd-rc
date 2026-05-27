use std::sync::LazyLock;

use rc_crypto::certificate::Certificate;

use crate::RootCertificate;

/// The PEM encoded R1 root certificate - see [`R1`].
pub const R1_PEM: &str = include_str!("../r1.crt");

/// The R1 root certificate.
///
/// ```text
/// Data:
///     Version: 3 (0x2)
///     Serial Number:
///         06:4e:6c:22:5e:17:6e:e6:ae:c3:23:73:87:58:5e:bc:63:e7:73:fb
///     Signature Algorithm: ecdsa-with-SHA256
///     Issuer: CN=Attestation Root R1, O=Datadog Inc., OU=Remote Config
///     Validity
///         Not Before: May 26 09:15:08 2026 GMT
///         Not After : May 21 09:15:08 2046 GMT
///     Subject: CN=Attestation Root R1, O=Datadog Inc., OU=Remote Config
///     Subject Public Key Info:
///         Public Key Algorithm: id-ecPublicKey
///             Public-Key: (256 bit)
///             pub:
///                 04:64:8b:ca:35:0b:e1:77:43:65:50:0f:0d:80:12:
///                 9a:6b:6d:03:67:a3:ea:7f:bb:3b:b8:ff:00:24:8c:
///                 73:8a:18:08:a4:08:b9:1b:7b:fe:b7:cf:9e:70:1e:
///                 7c:c1:6a:22:1b:05:db:92:01:56:fa:8c:79:85:e5:
///                 63:06:6a:03:5d
///             ASN1 OID: prime256v1
///             NIST CURVE: P-256
///     X509v3 extensions:
///         X509v3 Subject Key Identifier:
///             45:16:52:90:AE:19:FE:0C:CB:95:F0:15:E2:92:13:62:D1:BC:26:E6
///         X509v3 Authority Key Identifier:
///             45:16:52:90:AE:19:FE:0C:CB:95:F0:15:E2:92:13:62:D1:BC:26:E6
///         X509v3 Key Usage: critical
///             Certificate Sign, CRL Sign
///         X509v3 Basic Constraints: critical
///             CA:TRUE
/// Signature Algorithm: ecdsa-with-SHA256
/// Signature Value:
///     30:46:02:21:00:f3:0c:df:c0:b9:bf:07:2e:56:d6:40:86:1f:
///     c2:f7:43:28:90:71:ed:e0:90:8c:cb:ee:42:a3:a6:14:73:95:
///     73:02:21:00:be:8b:99:3f:a0:4f:f7:06:9c:4a:e5:6a:02:3d:
///     25:1e:e5:0a:8d:e0:a4:f0:71:67:85:c2:10:8f:50:3d:11:ba
/// sha256 Fingerprint=DD:69:43:CA:4F:83:95:EB:7E:A2:CC:CA:E0:4C:AB:32:74:DB:9B:4B:58:08:D6:6A:D8:96:65:EA:2A:04:C6:81
/// ```
pub static R1: LazyLock<RootCertificate> = LazyLock::new(|| {
    RootCertificate::from_trusted_cert(
        Certificate::from_pem(R1_PEM.as_bytes()).expect("invalid root r1 PEM"),
    )
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_fixture() {
        let want = "dd:69:43:ca:4f:83:95:eb:7e:a2:cc:ca:e0:4c:ab:32:74:db:9b:4b:58:08:d6:6a:d8:96:65:ea:2a:04:c6:81";
        let got = R1.fingerprint().to_string();
        assert_eq!(want, got);
    }
}
