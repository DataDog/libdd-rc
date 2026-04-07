#!/usr/bin/env bash
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
