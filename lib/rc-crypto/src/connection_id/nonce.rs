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

#[cfg(not(miri))]
use aws_lc_rs::rand;

/// A "number used once" for ID generation.
///
/// Specifically a 16 byte / 128 bit, cryptographically random value, used at
/// most once per connection.
#[derive(Debug)]
pub struct IdNonce([u8; 16]);

impl Default for IdNonce {
    #[cfg(not(miri))]
    fn default() -> Self {
        let mut buf = [0u8; 16];
        rand::fill(&mut buf).unwrap();

        assert_ne!(buf, [0u8; 16]);

        Self(buf)
    }

    /// Miri cannot cross the FFI boundary into the C implementation of AWS-LC.
    ///
    /// For the purposes of miri checks only, return a static nonce.
    #[cfg(miri)]
    fn default() -> Self {
        Self([42_u8; 16])
    }
}

impl IdNonce {
    /// Expose the inner bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use static_assertions::assert_not_impl_any;

    // A nonce should not be cloned, so that it can be consumed after one
    // verification attempt by moving ownership into the verification fn.
    assert_not_impl_any!(IdNonce: Clone);

    #[test]
    fn test_nonce_generation() {
        assert_eq!(IdNonce::default().as_bytes().len(), 16);

        // Rand is random:
        assert_ne!(IdNonce::default().as_bytes(), IdNonce::default().as_bytes());
    }
}
