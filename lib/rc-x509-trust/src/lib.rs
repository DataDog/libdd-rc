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
pub mod trust_store;

#[cfg(test)]
pub(crate) mod test_issuer;

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
