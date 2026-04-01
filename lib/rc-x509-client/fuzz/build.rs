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

//! Automated fuzz corpus generation.

use std::path::Path;

use rc_x509_proto::{
    encode,
    protocol::v1::{Ping, ServerToClient},
};
use twox_hash::XxHash64;

fn main() {
    ffi_io();
}

fn ffi_io() {
    let path = "corpus/ffi_io";
    std::fs::create_dir_all(path).expect("failed to create corpus dir");

    write_proto(path, ServerToClient { message: None });
    write_proto(
        path,
        ServerToClient {
            message: Some(
                rc_x509_proto::protocol::v1::server_to_client::Message::Ping(Ping::default()),
            ),
        },
    );
}

/// Serialise the value `v` using protobuf and write it to a deterministically
/// named file under `path`.
fn write_proto<P, T>(path: P, v: T)
where
    P: AsRef<Path>,
    T: rc_x509_proto::Serialisable + Default,
{
    const HASH_SEED: u64 = 42;

    let buf = encode(&v);
    let hash = XxHash64::oneshot(HASH_SEED, &buf);

    let path = path.as_ref().join(format!("_autogen_{hash}"));
    std::fs::write(path, buf).expect("failed to write corpus file")
}
