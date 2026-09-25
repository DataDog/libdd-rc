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

//! This module is responsible for processing [`ServerToClient`] messages from
//! the backend.
//!
//! [`ServerToClient`]: rc_x509_proto::protocol::v1::ServerToClient

mod fsm;
mod message_delegate;
mod retry;
mod state;
mod traits;

pub(crate) use message_delegate::MessageDelegate;
pub(super) use retry::retry_send;
