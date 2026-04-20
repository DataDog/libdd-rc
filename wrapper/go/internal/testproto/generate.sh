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

# Generates Go protobuf bindings from protocol.proto

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
PROTO_DIR="${REPO_ROOT}/lib/rc-x509-proto/protos"
PROTO_FILE="${PROTO_DIR}/protocol.proto"
OUT_DIR="${SCRIPT_DIR}"

export PATH="$(go env GOPATH)/bin:$PATH"
export PROTOC_GEN_GO="$(go env GOPATH)/bin/protoc-gen-go"

# Check required tools
if ! command -v protoc &>/dev/null; then
  echo "Error: protoc not installed" >&2
  echo "Install from: https://github.com/protocolbuffers/protobuf/releases" >&2
  exit 1
fi

if ! command -v protoc-gen-go &>/dev/null; then
  echo "Error: protoc-gen-go not installed" >&2
  echo "Install: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest" >&2
  exit 1
fi

echo "Generating Go protobuf bindings from ${PROTO_FILE}..."

set -x # output the command
protoc \
  --go_out="${OUT_DIR}" \
  --go_opt=paths=source_relative \
  --go_opt=Mprotocol.proto=github.com/DataDog/libdd-rc/wrapper/go/internal/testproto \
  -I"${PROTO_DIR}" \
  "${PROTO_FILE}"
