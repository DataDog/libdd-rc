#!/usr/bin/env zsh

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

echoe "pushing $TAG to origin"
git push origin "$TAG"

echoe "DONE"
