#!/usr/bin/env bash
# Copyright 2026 Datadog, Inc
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
# Updates all GitHub workflow files to use the Rust version specified in
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

# Find all workflow files
WORKFLOW_DIR="${REPO_ROOT}/.github/workflows"
if [[ ! -d "${WORKFLOW_DIR}" ]]; then
    echo "Error: ${WORKFLOW_DIR} not found" >&2
    exit 1
fi

# Update all workflow files that reference rust container images
UPDATED_COUNT=0
for workflow in "${WORKFLOW_DIR}"/*.yml; do
    if [[ ! -f "${workflow}" ]]; then
        continue
    fi

    # Check if this workflow uses rust container images
    if grep -q 'image: rust:' "${workflow}"; then
        echo "Updating ${workflow}..."

        # Replace rust:VERSION with the current version
        # Use a temporary file for atomic replacement
        tmp_file=$(mktemp)
        sed "s|image: rust:[0-9.]*|image: rust:${RUST_VERSION}|g" "${workflow}" > "${tmp_file}"
        mv "${tmp_file}" "${workflow}"

        UPDATED_COUNT=$((UPDATED_COUNT + 1))
    fi
done

if [[ ${UPDATED_COUNT} -eq 0 ]]; then
    echo "No workflow files needed updating."
else
    echo "Updated ${UPDATED_COUNT} workflow file(s) to use rust:${RUST_VERSION}"
fi
