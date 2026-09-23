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

#![allow(clippy::collapsible_if)]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

/// Locates the `.git` directory by walking up from `start`, and registers
/// the files that change when `HEAD` moves (via commit, checkout, merge,
/// etc) as build script rerun triggers.
///
/// Without this, cargo only reruns this build script when a file within
/// this crate changes, leaving [`env!("BUILD_GIT_COMMIT_HASH")`] stale
/// whenever `HEAD` advances without touching this crate.
fn rerun_if_head_changed(start: &Path) {
    let Some(git_dir) = start
        .ancestors()
        .map(|p| p.join(".git"))
        .find(|p| p.is_dir())
    else {
        return;
    };

    let head = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head.display());

    // `HEAD` is usually a symbolic ref (e.g. `ref: refs/heads/main`), whose
    // target file also needs to be watched to detect new commits on the
    // current branch. Packed refs are watched too, in case the branch's ref
    // has been packed.
    if let Ok(contents) = std::fs::read_to_string(&head) {
        if let Some(target) = contents.trim().strip_prefix("ref: ") {
            println!("cargo:rerun-if-changed={}", git_dir.join(target).display());
        }
    }
    println!(
        "cargo:rerun-if-changed={}",
        git_dir.join("packed-refs").display()
    );
}

fn main() {
    rerun_if_head_changed(&PathBuf::from(env!("CARGO_MANIFEST_DIR")));

    if let Some(v) = option_env!("_OVERRIDE_GIT_VERSION_HASH") {
        println!("cargo:rustc-env=BUILD_GIT_COMMIT_HASH={v}");
        return;
    }
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
