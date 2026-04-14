#!/usr/bin/env bash
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

#
# Updates the CI Dockerfile to use the Rust version specified in
# rust-toolchain.toml.
#
# Usage:
#   ./scripts/update-rust-version.sh

set -euo pipefail

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Extract the Rust version from rust-toolchain.toml
TOOLCHAIN_FILE="${REPO_ROOT}/rust-toolchain.toml"
if [[ ! -f "${TOOLCHAIN_FILE}" ]]; then
    echo "Error: ${TOOLCHAIN_FILE} not found" >&2
    exit 1
fi

# Parse the channel version from rust-toolchain.toml
RUST_VERSION=$(grep '^channel = ' "${TOOLCHAIN_FILE}" | sed 's/channel = "\(.*\)"/\1/')

if [[ -z "${RUST_VERSION}" ]]; then
    echo "Error: Could not extract Rust version from ${TOOLCHAIN_FILE}" >&2
    exit 1
fi

echo "Rust version from toolchain file: ${RUST_VERSION}"

# Update the container image tag in all workflow files
WORKFLOWS_DIR="${REPO_ROOT}/.github/workflows"
echo "Updating workflow files in ${WORKFLOWS_DIR}..."
for wf in "${WORKFLOWS_DIR}"/*.yml; do
    if grep -q 'ghcr.io/datadog/libdd-rc/rust-ci:' "${wf}"; then
        sed -i'' "s|ghcr.io/datadog/libdd-rc/rust-ci:[0-9.]*|ghcr.io/datadog/libdd-rc/rust-ci:${RUST_VERSION}|g" \
            "${wf}"
        echo "  Updated $(basename "${wf}")"
    fi
done

echo "Done — rebuild the CI image to pick up the change."
