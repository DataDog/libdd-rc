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

use std::sync::LazyLock;

use rc_crypto::certificate::Certificate;

use crate::RootCertificate;

/// The PEM encoded R2 root certificate - see [`R2`].
pub const R2_PEM: &str = include_str!("../r2.crt");

/// The R2 root certificate.
///
/// ```text
/// Data:
///     Version: 3 (0x2)
///     Serial Number:
///         3d:9f:1b:84:65:eb:f3:77:b3:c7:73:2f:41:74:3c:4e:33:d6:ec:ab
///     Signature Algorithm: ecdsa-with-SHA256
///     Issuer: CN=Attestation Root R2, O=Datadog Inc., OU=Remote Config
///     Validity
///         Not Before: May 26 09:25:11 2026 GMT
///         Not After : May 21 09:25:11 2046 GMT
///     Subject: CN=Attestation Root R2, O=Datadog Inc., OU=Remote Config
///     Subject Public Key Info:
///         Public Key Algorithm: id-ecPublicKey
///             Public-Key: (256 bit)
///             pub:
///                 04:9c:47:92:f6:e3:16:7f:5a:bc:02:dd:ee:07:7b:
///                 17:40:02:d0:65:29:87:d0:42:e4:6d:1b:78:66:6f:
///                 3f:23:b5:e5:af:ae:07:0a:ac:e1:cf:9b:cd:18:30:
///                 26:02:3d:55:63:fc:9f:46:b5:34:26:d4:0a:bc:84:
///                 ee:d4:be:b9:c1
///             ASN1 OID: prime256v1
///             NIST CURVE: P-256
///     X509v3 extensions:
///         X509v3 Subject Key Identifier:
///             D1:21:CD:E0:1F:B5:1F:F0:6E:72:63:74:D0:39:20:BB:77:29:19:9B
///         X509v3 Authority Key Identifier:
///             D1:21:CD:E0:1F:B5:1F:F0:6E:72:63:74:D0:39:20:BB:77:29:19:9B
///         X509v3 Key Usage: critical
///             Certificate Sign, CRL Sign
///         X509v3 Basic Constraints: critical
///             CA:TRUE
/// Signature Algorithm: ecdsa-with-SHA256
/// Signature Value:
///     30:45:02:20:7b:f3:a7:2a:39:1d:da:43:a6:29:00:83:8c:38:
///     56:0b:e4:53:09:f6:a1:c2:73:26:f6:ef:72:99:b5:42:71:8a:
///     02:21:00:ec:f4:eb:ee:03:8e:d9:f8:18:30:d9:2d:0a:e3:b9:
///     1d:7c:da:62:65:0a:5e:b3:3c:69:ca:c4:36:e9:c6:90:d2
/// sha256 Fingerprint=3B:ED:33:B6:9E:11:86:18:3A:64:75:7F:5C:D7:7E:2B:94:C8:7A:A5:53:3D:6B:BF:0A:F0:B1:EB:05:D5:65:8F
/// ```
pub static R2: LazyLock<RootCertificate> = LazyLock::new(|| {
    RootCertificate::from_trusted_cert(
        Certificate::from_pem(R2_PEM.as_bytes()).expect("invalid root r1 PEM"),
    )
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_fixture() {
        let want = "3b:ed:33:b6:9e:11:86:18:3a:64:75:7f:5c:d7:7e:2b:94:c8:7a:a5:53:3d:6b:bf:0a:f0:b1:eb:05:d5:65:8f";
        let got = R2.fingerprint().to_string();
        assert_eq!(want, got);
    }
}
