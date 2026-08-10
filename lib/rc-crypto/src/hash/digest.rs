use std::marker::PhantomData;

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

/// An `N`-byte hash digest produced using the `T` hash algorithm.
#[derive(Debug)]
pub struct Digest<const N: usize, T>
where
    T: HashAlgo<N>,
{
    digest: [u8; N],
    _algo: PhantomData<T>,
}

impl<const N: usize, T> Digest<N, T>
where
    T: HashAlgo<N>,
{
    /// Construct a [`Digest`] from a raw byte hash.
    pub(crate) fn from_raw(digest: [u8; N]) -> Self {
        Self {
            digest,
            _algo: PhantomData,
        }
    }

    /// Access the raw hash bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.digest
    }

    /// Return a reference to the fixed size backing array.
    pub fn as_array(&self) -> &[u8; N] {
        &self.digest
    }
}

impl<const N: usize, T> Clone for Digest<N, T>
where
    T: HashAlgo<N>,
{
    fn clone(&self) -> Self {
        Self {
            digest: self.digest,
            _algo: self._algo,
        }
    }
}

impl<const N: usize, T> std::hash::Hash for Digest<N, T>
where
    T: HashAlgo<N>,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

impl<const N: usize, T> Eq for Digest<N, T> where T: HashAlgo<N> {}

impl<const N: usize, T> PartialEq for Digest<N, T>
where
    T: HashAlgo<N>,
{
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}
