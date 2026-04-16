// Build script - generate C header
use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let crate_path = PathBuf::from(&crate_dir);
    let workspace_dir = crate_path
        .parent()
        .and_then(|p| p.parent())
        .expect("Failed to find workspace root");

    let output_file = workspace_dir.join("include/libdd_rc_test_harness.h");
    let config_path = workspace_dir.join("cbindgen.toml");

    // Point cbindgen to rc-x509-ffi crate to get all FFI functions
    let ffi_crate_dir = workspace_dir.join("lib/rc-x509-ffi");

    let config = cbindgen::Config::from_file(&config_path)
        .expect("Failed to load cbindgen.toml");

    cbindgen::Builder::new()
        .with_crate(ffi_crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&output_file);
}
