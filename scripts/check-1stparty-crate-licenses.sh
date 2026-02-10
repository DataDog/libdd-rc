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
# Enumerate the local rust crates in the workspace, and ensure they all have
# license metadata that specifies Apache 2.0.
#
# This script is used in CI.
#

set -euo pipefail

# Check that all first-party crates have license = "Apache-2.0" in their Cargo.toml
#
# Usage: ./check-crate-licenses.sh
#
# This script checks all workspace member crates to ensure they have the
# correct license field set in their Cargo.toml files.

# Check if we're in a workspace
if [ ! -f Cargo.toml ]; then
    echo "Error: No Cargo.toml found in current directory"
    exit 1
fi

echo "Checking license fields in workspace crates..."
echo

FAILED_MANIFESTS=()

# Get all workspace packages (not dependencies)
METADATA=$(cargo metadata --no-deps --format-version 1)
WORKSPACE_PACKAGES=$(echo "$METADATA" | jq -r '.packages[] | select(.source == null) | .name + "|" + .manifest_path')

if [ -z "$WORKSPACE_PACKAGES" ]; then
    echo "Error: No workspace packages found"
    exit 1
fi

# Check each workspace package
while IFS='|' read -r package_name manifest_path; do
    # Check if the license field exists and has the correct value
    LICENSE=$(grep -E '^license\s*=' "$manifest_path" | sed -E 's/^license\s*=\s*"([^"]+)".*/\1/' || echo )

    case "$LICENSE" in
        "Apache-2.0")
            echo "✓  $package_name: license = \"Apache-2.0\""
            ;;
        "")
            echo "✗  $package_name: Missing license field"
            FAILED_MANIFESTS+=("$manifest_path")
            ;;
        *)
            echo "✗  $package_name: Incorrect license '$LICENSE' (expected 'Apache-2.0')"
            FAILED_MANIFESTS+=("$manifest_path")
            ;;
    esac
done <<< "$WORKSPACE_PACKAGES"

echo

if [ ${#FAILED_MANIFESTS[@]} -eq 0 ]; then
    echo "✓ All crates have correct license fields"
    exit 0
else
    echo "✗ The following Cargo.toml files need license = \"Apache-2.0\":"
    for manifest in "${FAILED_MANIFESTS[@]}"; do
        echo "  - $manifest"
    done
    echo
    echo
    echo "Please add 'license = \"Apache-2.0\"' to the [package] section of each file"
    echo
    exit 1
fi
