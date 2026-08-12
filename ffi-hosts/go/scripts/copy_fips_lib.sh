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

# Copies the aws-lc-fips-sys crypto lib built by `cargo build -p rc-x509-ffi`
# to a version-agnostic name next to librc_x509_ffi.a, so bridge.go's LDFLAGS
# don't need updating when the aws-lc-fips-sys version in Cargo.lock changes.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
release_dir="target/release"

# The lib's filename is version-pinned (e.g. libaws_lc_fips_0_13_16_crypto),
# so match any version, across all cargo build dirs, and take the most
# recently built one -- stale build dirs from older aws-lc-fips-sys versions
# can linger on disk and would otherwise be picked arbitrarily.
fips_lib=$(find "$release_dir/build" \
	\( -name 'libaws_lc_fips_*crypto.dylib' -o -name 'libaws_lc_fips_*crypto.so' -o -name 'libaws_lc_fips_*crypto.a' \) \
	-exec ls -t {} + 2>/dev/null | head -n1)

if [ -z "$fips_lib" ]; then
	exit 0
fi

ext=${fips_lib##*.}
dest="$release_dir/libaws_lc_fips_crypto.$ext"
cp "$fips_lib" "$dest"

case "$ext" in
dylib)
	# The Go linker records the dylib's embedded install name (its
	# LC_ID_DYLIB), not the -l flag used to link it, so that also needs
	# rewriting to the version-agnostic name.
	install_name_tool -id "@rpath/libaws_lc_fips_crypto.dylib" "$dest"
	# install_name_tool invalidates the existing code signature; re-sign
	# ad hoc so dyld doesn't kill the process at load.
	codesign --force --sign - "$dest"
	;;
so)
	# Linux equivalent of the above: rewrite the embedded SONAME.
	patchelf --set-soname libaws_lc_fips_crypto.so "$dest" 2>/dev/null || true
	;;
esac
