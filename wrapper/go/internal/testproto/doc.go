// Copyright 2026-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package testproto contains generated protobuf bindings for the RC x509 protocol.
//
// The protocol.proto file is shared with the Rust implementation and located at
// lib/rc-x509-proto/protos/protocol.proto in the repository root.
//
// To regenerate the Go bindings when the proto file changes, run:
//
//	go generate ./internal/testproto
//
// This requires protoc and protoc-gen-go to be installed.
package testproto

//go:generate ./generate.sh
