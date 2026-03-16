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

use std::{fmt::Display, sync::OnceLock};

use aws_lc_rs::digest::{SHA256, digest};
use x509_parser::prelude::X509Certificate;

use crate::hex::colon_string;

/// The byte length of a fingerprint is always 32 for SHA256 digests.
const FINGERPRINT_LEN: usize = aws_lc_rs::digest::SHA256_OUTPUT_LEN;

/// A [`Fingerprint`] is a deterministic, fixed-length SHA-256 hash that
/// uniquely identifies a single issued [`Certificate`].
///
/// The fingerprint is constructed by hashing the (DER encoded) bytes of a
/// [`Certificate`], a process that is lightly described in [RFC 4387 § 2.2] as
/// a `certHash`. Unlike the RFC, we use SHA-256 as the hash instead of SHA-1 (a
/// common modification for newer systems, including new versions of OpenSSL).
///
/// A [`Fingerprint`] should be used when checking if two certificates are
/// identical.
///
/// [`Certificate`]: super::Certificate
/// [RFC 4387 § 2.2]: https://datatracker.ietf.org/doc/html/rfc4387#section-2.2
#[derive(Debug, Clone)]
pub struct Fingerprint {
    digest: [u8; FINGERPRINT_LEN],

    /// A lazily-rendered string representation of `digest`.
    ///
    /// See [`Self::as_hex_str()`] for initialisation.
    rendered: OnceLock<String>,
}

impl Fingerprint {
    /// Render the [`Fingerprint`] as a lowercase hex string delimited by
    /// colons in the style of OpenSSL.
    ///
    /// Example: `cc:cb:0f:63:f1:63:5e:f1:0e:26:e8:82:f7:7a:6e:f9`
    ///
    /// This value is lazily rendered and cached for reuse.
    pub fn as_hex_str(&self) -> &str {
        self.rendered.get_or_init(|| colon_string(self.as_bytes()))
    }

    /// Return the raw fingerprint digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.digest
    }
}

impl Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_hex_str())
    }
}

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl<'a> From<&'a X509Certificate<'a>> for Fingerprint {
    fn from(cert: &'a X509Certificate<'a>) -> Self {
        let hash = digest(&SHA256, cert.as_raw());

        Self {
            digest: hash
                .as_ref()
                .try_into()
                .expect("sha256 digest length is fixed"),
            rendered: Default::default(),
        }
    }
}

/// Render a [`Fingerprint`] as an encoded string in structured logging.
impl valuable::Valuable for Fingerprint {
    fn as_value(&self) -> valuable::Value<'_> {
        valuable::Value::String(self.as_hex_str())
    }

    fn visit(&self, visit: &mut dyn valuable::Visit) {
        visit.visit_value(self.as_value());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixture() {
        let input = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let f = Fingerprint {
            digest: input,
            rendered: Default::default(),
        };

        assert_eq!(f.as_bytes(), &input);

        let want = "01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20";
        assert_eq!(f.as_hex_str(), want);
        assert_eq!(f.to_string(), want);
    }
}
