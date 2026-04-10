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

#![doc = "../README.md"]
// Nothing is used yet.
#![allow(unused)]

mod abort_on_drop;
pub mod codec;
pub mod connection;
pub mod entrypoint;
pub mod host_runtime;
pub mod payload;
mod shutdown_signal;
pub mod trust;

pub use abort_on_drop::*;
pub use shutdown_signal::*;
