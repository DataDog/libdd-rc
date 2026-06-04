#!/usr/bin/env zsh
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


# Running this script will publish the crates in this repo to crates.io via CI,
# by creating a GitHub repo release which runs the automation.
#
# Requires "gh" to be installed and logged in, and tag push permissions.

set -euo pipefail

function echoe {
	print -P "%F{green}==>%f $*" >&2;
}

# Only publishing from the main branch is acceptable.
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$BRANCH" != "main" ]]; then
	echoe "%F{red}please only release the 'main' branch%f (currently on %F{blue}$BRANCH%f)"
	exit 1
fi

# Stop if the repo is not "clean" as this will impact the tag diff below, and
# it's likely the caller hasn't committed some change they want to publish.
if ! git diff --quiet || ! git diff --cached --quiet; then
	echoe "%F{red}repo has uncommitted changes - aborting%f"
	exit 1
fi

# Ensure the gh CLI is authenticated before doing any work - this is needed to
# publish the Github release from the tag.
if ! gh auth status &>/dev/null; then
	echoe "%F{red}not logged into gh - run 'gh auth login' first%f"
	exit 1
fi

echoe "fetching latest repo changes"
git fetch --tags origin

# Build the new tag name.
DATE=$(date '+%Y-%m-%d')
REF=$(git rev-parse --short main)
TAG="v0.2.0-$DATE.$REF"

echoe "this release will point at: %F{blue}$(git show --oneline $REF)%f"

# Find what has changed in this release.
LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null)
echoe "crate version changes since last release ($LAST_TAG):"
echo

# Build a map of crate -> version for the current repo state.
typeset -A CURRENT_VERSIONS
while read -r name ver; do
	CURRENT_VERSIONS[$name]=$ver
done < <(cargo metadata --format-version 1 --no-deps | jq -r '.packages[] | [.name, .version] | @tsv')

# Check out the repo at LAST_TAG (using a archive into a temp dir)
tmpdir=$(mktemp -d)
trap "rm -rf $tmpdir" EXIT
git archive "$LAST_TAG" | tar -x -C "$tmpdir"

# Build a map of crate -> version for the repo state at LAST_TAG.
typeset -A OLD_VERSIONS
while read -r name ver; do
	OLD_VERSIONS[$name]=$ver
done < <(cargo metadata --manifest-path "$tmpdir/Cargo.toml" --format-version 1 --no-deps 2>/dev/null | jq -r '.packages[] | [.name, .version] | @tsv')

# Show any changes.
CHANGES=0
for name in ${(k)CURRENT_VERSIONS}; do
	new_ver=${CURRENT_VERSIONS[$name]}
	old_ver=${OLD_VERSIONS[$name]:-}
	if [[ "$old_ver" != "$new_ver" ]]; then
		print -P "    %F{blue}$name%f: ${old_ver:-<new>} -> $new_ver" >&2
		(( ++CHANGES ))
	fi
done

echo

# Stop if no crates have changed - this release is useless.
if [[ $CHANGES -eq 0 ]] then;
	echoe "%F{red}no changes detected in this release - aborting%f"
	exit 1
fi

# Wait for confirmation of the diff
print -Pn "%F{yellow}proceed?%f [y/N] " >&2
read -r CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { echoe "%F{red}aborted%f"; exit 1; }

# Create the tag (signed).
echoe "creating signed tag: $TAG"
git tag -s "$TAG" -m "$TAG"

# Push the tag to the repo.
echoe "pushing $TAG to origin"
git push origin "$TAG"

# And use it to create a github release.
echoe "creating GitHub release"
gh release create "$TAG" --title "$TAG" --generate-notes

echoe "DONE"
