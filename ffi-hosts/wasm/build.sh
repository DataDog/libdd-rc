#!/usr/bin/env bash
#
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
# Build the rc-x509-ffi library for WebAssembly.
#
# Requires:
#   * rustup target add wasm32-wasip1-threads
#   * an LLVM clang with the WebAssembly backend (Apple clang does NOT have it)
#   * a wasi-libc sysroot, to build the aws-lc C sources against
#
# Override LLVM_DIR / WASI_SYSROOT if yours live elsewhere.

set -euo pipefail

TARGET=wasm32-wasip1-threads
LLVM_DIR="${LLVM_DIR:-/opt/homebrew/opt/llvm}"
WASI_SYSROOT="${WASI_SYSROOT:-/opt/homebrew/share/wasi-sysroot}"

# aws-lc needs OPENSSL_NO_SOCK / OPENSSL_NO_TTY: wasi-libc has no netdb.h or
# termios.h, and neither BIO sockets nor console I/O are used by this library.
export CC_wasm32_wasip1_threads="${LLVM_DIR}/bin/clang"
export AR_wasm32_wasip1_threads="${LLVM_DIR}/bin/llvm-ar"
export CFLAGS_wasm32_wasip1_threads="--sysroot=${WASI_SYSROOT} -DOPENSSL_NO_SOCK -DOPENSSL_NO_TTY -pthread"

cd "$(dirname "$0")/../.."

# Build as a cdylib to get a standalone .wasm module. This is a command line
# override of the crate-type in Cargo.toml, because cargo has no way to express
# a per-target crate-type, and the cdylib is of no use to the native builds.
#
# The feature selection is explicit: naming the package with -p applies that
# package's own defaults (default = ["fips"]) rather than the ones this crate
# selects for it, and aws-lc-fips-sys cannot target wasm at all.
cargo rustc --release --target "${TARGET}" --crate-type cdylib \
	-p rc-x509-ffi --no-default-features --features non-fips "$@"

echo
echo "built: $(pwd)/target/${TARGET}/release/rc_x509_ffi.wasm"
