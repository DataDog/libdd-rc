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

#![doc = include_str!("../README.md")]
#![allow(dead_code)]

pub mod cert;
pub mod chain;
mod endpoint_hostname;
pub mod trust_store;

pub use endpoint_hostname::*;

/// Render a [`valuable::Valuable`] type as a [`tracing`] field value.
///
/// When compiled with `--cfg tracing_unstable`, the value is recorded as
/// structured [`valuable`] data. Otherwise (as [`tracing`] cannot record
/// [`valuable`] data without it) the value is recorded using the [`Debug`]
/// representation of its [`valuable::Value`] instead.
pub(crate) trait AsLogValue: valuable::Valuable {
    /// Return the [`tracing`] field value for `self`.
    #[cfg(tracing_unstable)]
    fn as_log_value(&self) -> valuable::Value<'_> {
        self.as_value()
    }

    /// Return the [`tracing`] field value for `self`.
    #[cfg(not(tracing_unstable))]
    fn as_log_value(&self) -> tracing::field::DebugValue<valuable::Value<'_>> {
        tracing::field::debug(self.as_value())
    }
}

impl<T> AsLogValue for T where T: valuable::Valuable + ?Sized {}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use proptest::prelude::*;

    /// A value generator for [`Bytes`] fields on protobuf types (to satisfy the
    /// [`proptest::arbitrary::Arbitrary`] trait derived on all protobuf types).
    pub(crate) fn arbitrary_bytes(
        size: impl Into<prop::collection::SizeRange>,
    ) -> impl Strategy<Value = Bytes> {
        prop::collection::vec(any::<u8>(), size).prop_map(Bytes::from)
    }
}

#[cfg(feature = "fuzzing")]
mod fuzzing {
    use arbitrary::Arbitrary;
    use bytes::Bytes;

    /// Generate arbitrary [`Bytes`] for fuzzing byte payloads.
    ///
    /// While similarly named, this is a distinct trait / impl from proptest
    /// `Arbitrary` impls.
    pub(crate) fn arbitrary_bytes(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Bytes> {
        Ok(Vec::<u8>::arbitrary(u)?.into())
    }
}
