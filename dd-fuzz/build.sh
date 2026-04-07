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
# Build a Docker image for each fuzz target discovered in the repo.
#
# Fuzz targets are discovered by finding Cargo.toml files that contain
# cargo-fuzz = true, then extracting [[bin]] names from each.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_PREFIX="${IMAGE_PREFIX:-libdd-rc-fuzz}"
images=()

# Find all cargo-fuzz Cargo.toml files relative to repo root.
fuzz_tomls=$(grep -rl 'cargo-fuzz = true' "$REPO_ROOT" --include='Cargo.toml')

for toml in $fuzz_tomls; do
    fuzz_dir="$(dirname "$toml")"
    fuzz_dir_rel="${fuzz_dir#"$REPO_ROOT"/}"

    # Extract [[bin]] target names from the Cargo.toml.
    targets=$(grep -A1 '^\[\[bin\]\]' "$toml" | grep '^name' | sed 's/.*= *"\(.*\)"/\1/')

    for target in $targets; do
        image="${IMAGE_PREFIX}:${target}"
        echo "==> Building ${image} (dir=${fuzz_dir_rel}, target=${target})"
        podman build \
            --build-arg "FUZZ_DIR=${fuzz_dir_rel}" \
            --build-arg "FUZZ_TARGET=${target}" \
            -f "${SCRIPT_DIR}/Dockerfile" \
            -t "${image}" \
            "$REPO_ROOT"
        images+=("${image}")
    done
done

echo ""
echo "Built ${#images[@]} image(s):"
for image in "${images[@]}"; do
    echo "  ${image}"
done
