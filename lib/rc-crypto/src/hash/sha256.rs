use aws_lc_rs::digest::SHA256;

use crate::hash::{Digest, HashAlgo, Sealed};

/// The byte size of a [`Sha256`] hash.
pub const SHA256_OUTPUT_LEN: usize = aws_lc_rs::digest::SHA256_OUTPUT_LEN;

/// A [`Digest`] type specialised for [`Sha256`].
pub type Sha256Hash = Digest<SHA256_OUTPUT_LEN, Sha256>;

/// SHA256 hash algorithm.
#[derive(Debug)]
pub struct Sha256;

impl Sealed for Sha256 {}

impl HashAlgo<SHA256_OUTPUT_LEN> for Sha256 {
    fn hash(data: &[u8]) -> Digest<SHA256_OUTPUT_LEN, Self> {
        let digest = aws_lc_rs::digest::digest(&SHA256, data)
            .as_ref()
            .try_into()
            .expect("sha256 digest is 32 bytes");

        Digest::from_raw(digest)
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
            mut input in prop::collection::vec(any::<u8>(), 0..258),
        ) {
            let a = Sha256::hash(&input[..]);
            let b = Sha256::hash(&input[..]);

            assert_eq!(a, b); // Deterministic hashes

            input.push(42);
            let c = Sha256::hash(&input);

            assert_ne!(a, c); // Not equal after modification
        }
    }
}
