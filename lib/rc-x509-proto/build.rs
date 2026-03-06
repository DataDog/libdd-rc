//! Protobuf compilation / codegen.

fn main() -> std::io::Result<()> {
    prost_build::compile_protos(&["protos/protocol.proto"], &["protos/"])?;
    Ok(())
}
