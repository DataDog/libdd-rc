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
