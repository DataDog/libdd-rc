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

use aws_lc_rs::digest::{Context, SHA256};

use crate::hash::{Digest, HashAlgo, IncrementalHashState, Sealed};

/// The byte size of a [`Sha256`] hash.
pub const SHA256_OUTPUT_LEN: usize = aws_lc_rs::digest::SHA256_OUTPUT_LEN;

/// A [`Digest`] type specialised for [`Sha256`].
pub type Sha256Hash = Digest<SHA256_OUTPUT_LEN, Sha256>;

/// SHA256 hash algorithm.
#[derive(Debug)]
pub struct Sha256;

impl Sealed for Sha256 {}

impl HashAlgo<SHA256_OUTPUT_LEN> for Sha256 {
    type Context<D> = Sha256State;

    fn incremental() -> Self::Context<Self> {
        Sha256State(Context::new(&SHA256))
    }
}

/// Incremental hash state.
///
/// This type can only be constructed via [`IncrementalHashAlgo`].
pub struct Sha256State(aws_lc_rs::digest::Context);

impl std::fmt::Debug for Sha256State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Sha256State").finish()
    }
}

impl IncrementalHashState<SHA256_OUTPUT_LEN, Sha256> for Sha256State {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finish(self) -> Digest<SHA256_OUTPUT_LEN, Sha256> {
        Digest::from_raw(
            self.0
                .finish()
                .as_ref()
                .try_into()
                .expect("sha256 digest is 32 bytes"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn test_fixture() {
        let input = b"bananas";
        let got = Sha256::hash(&input[..]);

        let want = [
            228, 186, 92, 189, 37, 28, 152, 230, 205, 28, 35, 241, 38, 163, 184, 29, 141, 131, 40,
            171, 201, 83, 135, 34, 152, 80, 149, 43, 62, 249, 249, 4,
        ];

        assert_eq!(want, got.as_bytes());
    }

    proptest! {
        #[test]
        fn prop_hash(
            input in prop::collection::vec(any::<u8>(), 0..258),
        ) {
            let a = Sha256::hash(&input[..]);
            let b = Sha256::hash(&input[..]);

            assert_eq!(a, b); // Deterministic hashes

            // Hash a modified input.
            let mut modified = input.clone();
            modified.push(42);
            let c = Sha256::hash(&modified);

            assert_ne!(a, c); // Modified buffer hash != unmodified.

            // Construct the modified hash incrementally:
            let mut inc = Sha256::incremental();
            inc.update(&input);
            inc.update(&[42]);

            let d = inc.finish();
            assert_eq!(c, d); // Incremental hash matches one-shot hash
        }
    }
}
