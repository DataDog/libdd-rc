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


# Running this script releases a new version of the Go module in ffi-hosts/go
# by pushing a signed "ffi-hosts/go/vX.Y.Z" tag.
#
# Usage: scripts/release-go.sh vX.Y.Z
#
# The tag is placed on the commit of the latest crate release tag (created by
# release.sh), so the Go module and the Rust crates it links against are
# released from the same commit. Run release.sh first.
#
# Requires git commit signing to be configured, and tag push permissions.

set -euo pipefail

function echoe {
	print -P "%F{green}==>%f $*" >&2;
}

VERSION="${1:-}"
if [[ ! "$VERSION" =~ '^v[01]\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ]]; then
	echoe "%F{red}usage: $0 vX.Y.Z%f"
	exit 1
fi
TAG="ffi-hosts/go/$VERSION"

echoe "fetching latest repo changes"
git fetch --tags origin

# The new version must be newer than the latest Go module release.
LAST_TAG=$(git tag --list 'ffi-hosts/go/v*' --sort=-v:refname | head -n 1)
LAST_VERSION="${LAST_TAG#ffi-hosts/go/}"
if [[ "$(printf '%s\n%s\n' "$LAST_VERSION" "$VERSION" | sort -V | tail -n 1)" != "$VERSION" || "$LAST_VERSION" == "$VERSION" ]]; then
	echoe "%F{red}$VERSION is not newer than the latest release ($LAST_TAG)%f"
	exit 1
fi

# Release from the commit of the latest crate release.
CRATE_TAG=$(git describe --tags --abbrev=0 --match 'v[0-9]*' origin/main)
COMMIT=$(git rev-list -n 1 "$CRATE_TAG")
echoe "this release will point at: %F{blue}$(git show --no-patch --oneline "$COMMIT")%f (crate release $CRATE_TAG)"

# Find what has changed in this release.
if [[ -n "$LAST_TAG" ]]; then
	CHANGES=$(git log --oneline "$LAST_TAG..$COMMIT" -- ffi-hosts/go)
else
	CHANGES=$(git log --oneline "$COMMIT" -- ffi-hosts/go)
fi
if [[ -z "$CHANGES" ]]; then
	echoe "%F{red}no changes to ffi-hosts/go between $LAST_TAG and crate release $CRATE_TAG - aborting%f"
	echoe "if ffi-hosts/go has changed on main since, run release.sh first"
	exit 1
fi
echoe "changes to ffi-hosts/go since $LAST_TAG:"
echo
print -r -- "$CHANGES" >&2
echo

# Wait for confirmation.
print -Pn "%F{yellow}release $TAG?%f [y/N] " >&2
read -r CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { echoe "%F{red}aborted%f"; exit 1; }

echoe "creating signed tag: $TAG"
git tag -s "$TAG" -m "$TAG" "$COMMIT"

echoe "pushing $TAG to origin"
git push origin "refs/tags/$TAG"
