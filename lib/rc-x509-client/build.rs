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
    let git_call = Command::new("git").args(["rev-parse", "HEAD"]).output();

    // Check if the execution succeeded (Ok) and if it did, check if the git
    // command returned 0, else capture the error output.
    let err = match git_call {
        Ok(output) if output.status.success() => {
            let hash = String::from_utf8_lossy(&output.stdout);
            println!("cargo:rustc-env=BUILD_GIT_COMMIT_HASH={hash}");
            None
        }
        Ok(output) => Some(String::from_utf8_lossy(&output.stderr).to_string()),
        Err(e) => Some(e.to_string()),
    };

    // The hash couldn't be read, because of the error output in "err".
    if let Some(err) = err {
        // If there is a build-time override set, use this value:
        if let Some(v) = option_env!("_OVERRIDE_GIT_VERSION_HASH") {
            println!("cargo:rustc-env=BUILD_GIT_COMMIT_HASH={v}");
        } else {
            // else the build is broken.
            println!("cargo:warning=client will have no embedded commit hash: {err}");
        }
    }
}
