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

# Generate LICENSE-3rdparty.csv from Cargo dependencies
#
# Usage:
#   ./generate-3rdparty-licenses.sh        # fix mode (default) - generates LICENSE-3rdparty.csv
#   ./generate-3rdparty-licenses.sh check  # check mode - verifies LICENSE-3rdparty.csv is up to date
#
# This script requires cargo-license to be installed:
#   cargo install cargo-license
#
# It also requires jq for JSON processing:
#   apt-get install jq  # Debian/Ubuntu
#   brew install jq     # macOS

MODE="${1:-fix}"
OUTPUT_FILE="LICENSE-3rdparty.csv"

# Check if cargo-license is installed
if ! command -v cargo-license &> /dev/null; then
    echo "Error: cargo-license is not installed"
    echo "Please run: cargo install cargo-license"
    exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed"
    echo "Please install jq (apt-get install jq or brew install jq)"
    exit 1
fi

# Function to generate the license CSV content.
#
# $1: path to CSV file to create
generate_licenses() {
    local output="$1"
    echo "Component,Origin,License,Copyright" > "$output"
    cargo license --json | jq -r '.[] | [.name, .repository // "N/A", .license, .authors // "N/A"] | @csv' | sort >> "$output"
}

case "$MODE" in
    check)
        echo "Checking if $OUTPUT_FILE is up to date..."

        # Check if the file exists
        if [ ! -f "$OUTPUT_FILE" ]; then
            echo "::error::$OUTPUT_FILE is missing from the repository"
            echo ""
            echo ""
            echo "Please run: ./scripts/generate-3rdparty-licenses.sh"
            exit 1
        fi

        # Generate to a temporary file
        TEMP_FILE=$(mktemp)
        trap "rm -f $TEMP_FILE" EXIT

        generate_licenses "$TEMP_FILE"

        # Compare the files
        if ! diff -q "$OUTPUT_FILE" "$TEMP_FILE" > /dev/null; then
            echo "::error::$OUTPUT_FILE is out of date"
            echo ""
            echo "Differences:"
            diff -u "$OUTPUT_FILE" "$TEMP_FILE" || true
            echo ""
            echo ""
            echo "Please run: ./scripts/generate-3rdparty-licenses.sh"
            exit 1
        fi

        echo "✓ $OUTPUT_FILE is up to date"
        ;;

    fix)
        echo "Generating $OUTPUT_FILE..."
        generate_licenses "$OUTPUT_FILE"
        echo "✓ $OUTPUT_FILE has been generated successfully"
        echo ""
        echo "Please review the file and commit it to the repository."
        ;;

    *)
        echo "Error: Invalid mode '$MODE'. Use 'fix' or 'check'"
        exit 1
        ;;
esac
