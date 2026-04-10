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

use aws_lc_rs::{
    rand,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair},
};

use crate::{Signature, keys::public::PublicKey, signer::Signer};

pub(crate) const KEY_TYPE: &EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_ASN1_SIGNING;

/// A private ECDSA-P256 key.
///
/// # Encoding
///
/// These variable-length signatures use SHA256 internally, and are encoded
/// using ASN.1 wrapped DER bytes as described in [RFC 3279 § 2.2.3].
///
/// [RFC 3279 § 2.2.3]: https://tools.ietf.org/html/rfc3279#section-2.2.3
#[derive(Debug)] // Debug doesn't leak private key
pub struct PrivateKey {
    /// An ECDSA-P256 key pair, internally encoded as a PKCS#8 document.
    key: EcdsaKeyPair,
}

impl Default for PrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateKey {
    /// Generate a new, ephemeral key.
    pub fn new() -> Self {
        #[cfg(not(feature = "non-fips"))] // Fake non-FIPS in dd-source
        assert!(
            aws_lc_rs::try_fips_mode().is_ok(),
            "crypto module must be in FIPS mode"
        );

        let rand = rand::SystemRandom::new();
        let raw =
            EcdsaKeyPair::generate_pkcs8(KEY_TYPE, &rand).expect("ecdsa key generation failed");

        let key = EcdsaKeyPair::from_pkcs8(KEY_TYPE, raw.as_ref()).expect("invalid pkcs8");

        Self { key }
    }

    /// Return the [`PublicKey`] derived from this [`PrivateKey`].
    pub fn public_key(&self) -> PublicKey<'_> {
        PublicKey::new(self.key.public_key().as_ref())
    }
}

impl Signer for PrivateKey {
    fn sign(&self, data: &[u8]) -> Signature {
        let rand = rand::SystemRandom::new();

        Signature::from(
            self.key
                .sign(&rand, data)
                .expect("signature generation failed"),
        )
    }

    fn public_key(&self) -> PublicKey<'_> {
        PrivateKey::public_key(self)
    }
}

impl rcgen::SigningKey for PrivateKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(<PrivateKey as Signer>::sign(self, msg).as_ref().to_vec())
    }
}

impl rcgen::PublicKeyData for PrivateKey {
    fn der_bytes(&self) -> &[u8] {
        self.key.public_key().as_ref()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.public_key().algorithm()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Return a specific private key, deterministic across test runs.
    pub(crate) fn fixture_key() -> PrivateKey {
        const PKCS8_KEY: &[u8] = &[
            48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72,
            206, 61, 3, 1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32, 243, 225, 70, 195, 91, 136, 168,
            153, 187, 153, 116, 229, 57, 167, 13, 216, 27, 239, 144, 198, 203, 121, 64, 198, 7,
            111, 75, 160, 18, 140, 203, 253, 161, 68, 3, 66, 0, 4, 191, 188, 109, 191, 201, 131,
            85, 74, 84, 241, 161, 173, 189, 81, 122, 100, 128, 86, 229, 222, 41, 122, 152, 53, 210,
            162, 198, 133, 186, 162, 195, 21, 4, 213, 175, 88, 65, 194, 57, 232, 116, 80, 167, 165,
            193, 161, 175, 12, 225, 178, 55, 131, 212, 251, 75, 94, 140, 105, 227, 223, 67, 234,
            183, 132,
        ];

        let key = EcdsaKeyPair::from_pkcs8(KEY_TYPE, PKCS8_KEY).expect("ecdsa key load failed");

        PrivateKey { key }
    }

    /// Assert a key can be generated without panicking.
    #[test]
    fn test_generation() {
        let key = PrivateKey::default();
        let _pub = key.public_key();
    }

    /// Fixture test on the key type + hash algorithm used.
    ///
    /// This parameter MUST be FIPS compliant.
    #[test]
    fn test_fips_fixture() {
        assert_eq!(*KEY_TYPE, ECDSA_P256_SHA256_ASN1_SIGNING);
    }
}
