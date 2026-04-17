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

    let mut config = cbindgen::Config::from_file(&config_path)
        .expect("Failed to load cbindgen.toml");

    config.header = Some(format!(
        r#"/* Copyright 2026-Present Datadog, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * libdd-rc - Remote Configuration Client Library Test Harness
 *
 * C FFI interface for testing the Datadog Remote Configuration X509 client library.
 */

#include "libdd_rc.h"
"#
    ));
    config.include_guard = Some("LIBDD_RC_TEST_HARNESS_H".to_string());

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&output_file);
}
