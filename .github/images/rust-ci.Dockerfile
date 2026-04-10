# Copyright 2026-Present Datadog, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Pre-built CI image with our build dependencies.
#
# Built by the ci-image.yml workflow and published to GHCR. Using a pre-built
# image avoids re-installing these packages (~30s) on every CI run.
#
# To add a tool / dependency to the container image for your PR:
#
#   1. Add it to this Dockerfile below and open a PR.
#   2. Merge to main; the ci-image.yml action will run and push the new image.
#   3. Open your PR (or re-run CI) once the CI image is built.
#
# To perform a test build locally:
#
#   docker build -f .github/images/rust-ci.Dockerfile \
#     --build-arg RUST_VERSION=1.93.0 \
#     -t ghcr.io/datadog/libdd-rc/rust-ci:1.93.0 .
#

ARG RUST_VERSION=1.93.0
FROM rust:${RUST_VERSION}

RUN apt-get update && apt-get install -y --no-install-recommends \
    # local "act" runs of workflows
    nodejs \
    zstd \
    # licence scripts in CI
    jq \
    ##################
    # Crate deps
    \
    # rc_crypto -> aws-lc-rs deps
    clang \
    cmake \
    golang-go \
    # rc-x509-proto -> prost deps
    protobuf-compiler \
    #
    ##################
    # cleanup
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy \
    && rustup toolchain install nightly \
    && rustup +nightly component add miri

RUN cargo install cargo-fuzz --all-features \
    && cargo install --git https://github.com/EmbarkStudios/cargo-deny --rev 8e63a579d8ac61faa6e00d3d4ecde495bf138540 cargo-deny
