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

//! Compile-time build steps.

use std::process::Command;

fn main() {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("failed to exec git");

    assert!(
        output.status.success(),
        "git commit lookup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let hash = String::from_utf8_lossy(&output.stdout);
    println!("cargo:rustc-env=BUILD_GIT_COMMIT_HASH={hash}");
}
