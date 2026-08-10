use crate::hash::Digest;

/// A hash algorithm with a fixed byte length.
#[allow(private_bounds)]
pub trait HashAlgo<const N: usize>: std::fmt::Debug + Send + Sync + Sized + Sealed {
    /// Hash `data`, returning the [`Digest`] computed using this hash
    /// algorithm.
    fn hash(data: &[u8]) -> Digest<N, Self>;
}

/// All impls of the [`HashAlgo`] trait come from `rc-crypto` to ensure the FIPS
/// crypto backend is used.
pub(super) trait Sealed {}
