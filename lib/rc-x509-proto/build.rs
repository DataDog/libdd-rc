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
        "rc.x509.magic_tunnel.v1.MagicTunnelRequest.payload",
        "rc.x509.protocol.v1.Certificate.der",
        "rc.x509.protocol.v1.ClientHello.nonce",
        "rc.x509.protocol.v1.ClientHello.reconnection_data",
        "rc.x509.protocol.v1.ClientHello.version_commit",
        "rc.x509.protocol.v1.ClientHelloAck.server_nonce",
        "rc.x509.protocol.v1.ConnectionId.uuid_v8",
        "rc.x509.protocol.v1.DispatchRequest.encoded_dispatch_request",
        "rc.x509.protocol.v1.SetReconnectionData.opaque",
        "rc.x509.signature.v1.DetachedSignature.cert_id",
        "rc.x509.signature.v1.DetachedSignature.signature",
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

    config.type_attribute(
        "rc.x509.signature.v1.DetachedSignature",
        "#[derive(serde::Serialize, serde::Deserialize)]",
    );

    // Discover all the protobuf files.
    let mut protos = vec![];
    for entry in glob("protos/**/*.proto").expect("invalid glob") {
        let v = entry?;
        let v = v.to_str().expect("valid unicode path");

        println!("cargo::rerun-if-changed={v}");
        protos.push(v.to_owned());
    }

    // Export a `FileDescriptorSet` so downstream crates can reference these
    // message types with `extern_path_with_descriptor()`.
    let out_dir = std::env::var_os("OUT_DIR")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "OUT_DIR not set"))?;
    let descriptor_path = std::path::PathBuf::from(out_dir).join("rc_x509_proto_descriptor.bin");
    config
        .bytes(["."])
        .type_attribute(".", "#[derive(proptest_derive::Arbitrary)]")
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&protos, &["protos"])?;

    Ok(())
}
