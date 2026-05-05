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

use glob::glob;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();

    // A list of paths to fields that use `Bytes`, which need a manual impl of
    // Arbitrary defined to avoid compilation errors caused by derive(Arbitrary)
    // not being implemented for Bytes.
    let bytes_fields = [
        "rc.x509.protocol.v1.Certificate.der",
        "rc.x509.magic_tunnel.v1.MagicTunnelRequest.payload",
    ];
    for v in bytes_fields {
        config.field_attribute(v, r#"#[proptest(strategy = "crate::arbitrary_bytes()")]"#);
    }

    // The `response` field is inside a `oneof`, so it becomes an enum variant
    // (`Result::Response(Bytes)`) rather than a struct field. The proptest
    // `strategy` attribute on an enum variant must produce the full enum value,
    // not just the inner field, so we use a dedicated helper.
    config.field_attribute(
        "rc.x509.magic_tunnel.v1.MagicTunnelResponse.result.response",
        r#"#[proptest(strategy = "crate::arbitrary_oneof_bytes(Self::Response)")]"#,
    );

    // Discover all the protobuf files.
    let mut protos = vec![];
    for entry in glob("protos/**/*.proto").expect("invalid glob") {
        let v = entry?;
        let v = v.to_str().expect("valid unicode path");

        println!("cargo::rerun-if-changed={v}");
        protos.push(v.to_owned());
    }

    config
        .bytes(["."])
        .type_attribute(".", "#[derive(proptest_derive::Arbitrary)]")
        .compile_protos(&protos, &["protos"])?;

    Ok(())
}
