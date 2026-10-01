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

#![doc = "../README.md"]

mod abort_on_drop;
mod app_info;
mod build_version;
pub mod codec;
pub mod connection;
pub mod dispatch;
pub mod entrypoint;
pub mod host_runtime;
mod metrics;
mod shutdown_signal;

pub use abort_on_drop::*;
pub use shutdown_signal::*;

#[cfg(test)]
mod mocks;

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use tokio_util::bytes::Bytes;

    pub(crate) fn arbitrary_bytes(
        size: impl Into<prop::collection::SizeRange>,
    ) -> impl Strategy<Value = Bytes> {
        prop::collection::vec(any::<u8>(), size).prop_map(Bytes::from)
    }
}

#[cfg(feature = "fuzzing")]
mod fuzzing {
    use arbitrary::Arbitrary;
    use tokio_util::bytes::Bytes;

    /// Generate arbitrary [`Bytes`] for fuzzing byte payloads.
    ///
    /// While similarly named, this is a distinct trait / impl from proptest
    /// `Arbitrary` impls.
    pub(crate) fn arbitrary_bytes(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Bytes> {
        Ok(Vec::<u8>::arbitrary(u)?.into())
    }
}
