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

//! Protobuf compilation / codegen.

fn main() -> std::io::Result<()> {
    println!("cargo::rerun-if-changed=protos/protocol.proto");

    let mut config = prost_build::Config::new();

    // A list of paths to fields that use `Bytes`, which need a manual impl of
    // Arbitrary defined to avoid compilation errors caused by derive(Arbitrary)
    // not being implemented for Bytes.
    let bytes_fields = ["rc.x509.protocol.v1.Certificate.der"];
    for v in bytes_fields {
        config.field_attribute(v, r#"#[proptest(strategy = "crate::arbitrary_bytes()")]"#);
    }

    config
        .bytes(["."])
        .type_attribute(".", "#[derive(proptest_derive::Arbitrary)]")
        .compile_protos(&["protos/protocol.proto"], &["protos/"])?;

    Ok(())
}
