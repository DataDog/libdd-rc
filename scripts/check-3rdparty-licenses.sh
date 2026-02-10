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

set -euo pipefail

# Check that all third-party dependencies have approved licenses
#
# Usage: ./check-3rdparty-licenses.sh
#
# This script reads LICENSE-3rdparty.csv and verifies that all listed
# dependencies have licenses that are approved for use in this project.

LICENSE_FILE="LICENSE-3rdparty.csv"

# Approved licenses
APPROVED_LICENSES=(
    "Apache-2.0"
    "MIT"
    "BSD-2-Clause"
    "BSD-3-Clause"
    "Apache-2.0 OR MIT"
    "MIT OR Apache-2.0"
)

echo "Checking dependency licenses in $LICENSE_FILE..."
echo ""

if [ ! -f "$LICENSE_FILE" ]; then
    echo "Error: $LICENSE_FILE not found"
    exit 1
fi

FAILED_COMPONENTS=()
LINE_NUM=0

# Read the CSV file, skipping the header
while IFS=',' read -r component origin license copyright; do
    LINE_NUM=$((LINE_NUM + 1))

    # Skip header line
    if [ $LINE_NUM -eq 1 ]; then
        continue
    fi

    # Skip empty lines
    if [ -z "$component" ]; then
        continue
    fi

    # Remove quotes from fields
    component=$(echo "$component" | tr -d '"')
    license=$(echo "$license" | tr -d '"')

    # Skip first-party crates (they don't have a license in the CSV)
    if [ -z "$license" ] || [ "$license" = "N/A" ]; then
        continue
    fi

    # Check if license is approved
    LICENSE_APPROVED=false
    for approved in "${APPROVED_LICENSES[@]}"; do
        if [ "$license" = "$approved" ]; then
            LICENSE_APPROVED=true
            break
        fi
    done

    if [ "$LICENSE_APPROVED" = true ]; then
        echo "✓  $component: $license"
    else
        echo "✗  $component: $license (NOT APPROVED)"
        FAILED_COMPONENTS+=("$component ($license)")
    fi
done < "$LICENSE_FILE"

echo ""

if [ ${#FAILED_COMPONENTS[@]} -eq 0 ]; then
    echo "✓ All dependencies have approved licenses"
    exit 0
else
    echo "✗ The following dependencies have unapproved licenses:"
    for component in "${FAILED_COMPONENTS[@]}"; do
        echo "  - $component"
    done
    echo ""
    echo "Approved licenses: ${APPROVED_LICENSES[*]}"
    exit 1
fi
