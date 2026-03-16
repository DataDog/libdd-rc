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

use aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1;

use crate::{Signature, keys::KeyId};

/// Verifying a signature failed.
///
/// This error SHOULD be treated as a security concern and SHOULD be logged.
#[derive(Debug, thiserror::Error)]
#[error("signature verification failed")]
pub struct SignatureVerifyErr;

/// The public portion of a [`PrivateKey`].
///
/// # Internal Encoding
///
/// This key holds the raw DER key material bytes (without algorithm
/// identifier).
///
/// Specifically this holds the `subjectPublicKey` bit string field of the
/// `SubjectPublicKeyInfo` ASN.1 message as defined in [RFC 5280 § 4.1].
///
/// [RFC 5280 § 4.1]: https://tools.ietf.org/html/rfc5280#section-4.1
/// [`PrivateKey`]: crate::keys::PrivateKey
#[derive(Debug)]
pub struct PublicKey<'a>(&'a [u8]);

impl<'a> PublicKey<'a> {
    /// Construct this wrapper over opaque bytes.
    ///
    /// NOTE: this func is private to the crate to prevent constructing public
    /// keys incorrectly.
    pub(crate) fn new(v: &'a [u8]) -> Self {
        Self(v)
    }

    /// Verify that this key pair generated `sig` over `data`.
    pub fn verify(&self, data: &[u8], sig: &Signature) -> Result<(), SignatureVerifyErr> {
        aws_lc_rs::signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, self.0)
            .verify(data, sig.as_ref())
            .map_err(|_| SignatureVerifyErr)
    }

    /// Generate a [`KeyId`] that uniquely identifies this key, suitable for use
    /// as an X509 Subject Key Identifier.
    pub fn key_id(&self) -> KeyId {
        KeyId::from(self)
    }
}

impl<'a> rcgen::PublicKeyData for PublicKey<'a> {
    fn der_bytes(&self) -> &[u8] {
        self.0
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Signature, Signer,
        keys::{PrivateKey, tests::fixture_key},
    };

    /// Ensure a fixed key & signature can be used to verify a payload.
    ///
    /// It is unlikely the underlying library would break this, but changing the
    /// parameters used might.
    #[test]
    fn test_verify_fixture() {
        const SIG: &[u8] = &[
            48, 70, 2, 33, 0, 159, 76, 25, 247, 14, 167, 0, 24, 61, 234, 149, 155, 10, 245, 27,
            172, 116, 5, 107, 196, 201, 234, 169, 89, 6, 10, 214, 0, 134, 101, 141, 210, 2, 33, 0,
            208, 252, 87, 7, 41, 104, 204, 68, 230, 200, 114, 145, 230, 146, 74, 188, 121, 72, 16,
            186, 227, 169, 81, 231, 126, 133, 63, 65, 174, 55, 181, 207,
        ];

        let key = fixture_key();
        let sig = Signature::try_from(SIG).expect("valid signature");

        assert!(key.public_key().verify("bananas".as_bytes(), &sig).is_ok());
    }

    #[test]
    fn test_non_deterministic_signatures() {
        const DATA: [u8; 4] = [0x00, 0xCA, 0xFE, 0x42];

        let key = PrivateKey::new();

        let a = key.sign(&DATA);
        let b = key.sign(&DATA);
        assert_ne!(a, b);
    }
}
