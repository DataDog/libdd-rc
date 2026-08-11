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
mod build_version;
pub mod codec;
pub mod connection;
pub mod dispatch;
pub mod entrypoint;
pub mod host_runtime;
mod shutdown_signal;

pub use abort_on_drop::*;
pub use shutdown_signal::*;

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use tokio_util::bytes::Bytes;
    use uuid::Uuid;

    pub(crate) fn arbitrary_bytes() -> impl Strategy<Value = Bytes> {
        prop::collection::vec(any::<u8>(), 0..1028).prop_map(Bytes::from)
    }

    pub(crate) fn arbitrary_uuid_v8() -> impl Strategy<Value = Uuid> {
        any::<[u8; 16]>().prop_map(Uuid::new_v8)
    }
}
