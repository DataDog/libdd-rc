use crate::hash::Digest;

/// A hash algorithm with a fixed byte length output.
#[allow(private_bounds)]
pub trait HashAlgo<const N: usize>: std::fmt::Debug + Send + Sync + Sized + Sealed {
    /// The state container for the incremental hash.
    type Context<D>: IncrementalHashState<N, Self>;

    /// Begin a new incrementally constructed hash.
    ///
    /// Using this trait always more efficient than the one-shot
    /// [`HashAlgo::hash()`] method when hashing multiple byte slices into one
    /// [`Digest`].
    fn incremental() -> Self::Context<Self>;

    /// Hash `data`, returning the [`Digest`] computed using this hash
    /// algorithm.
    fn hash(data: &[u8]) -> Digest<N, Self> {
        let mut ctx = Self::incremental();
        ctx.update(data);
        ctx.finish()
    }
}

/// All impls of the [`HashAlgo`] trait come from `rc-crypto` to ensure the FIPS
/// crypto backend is used.
pub(super) trait Sealed {}

/// An incomplete incremental hash.
pub trait IncrementalHashState<const N: usize, D>
where
    D: HashAlgo<N>,
{
    /// Update the hash state to include `data`.
    fn update(&mut self, data: &[u8]);

    /// Finalise the hash to return the completed [`Digest`].
    fn finish(self) -> Digest<N, D>;
}
