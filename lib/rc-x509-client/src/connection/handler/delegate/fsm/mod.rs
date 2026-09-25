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

//! States of the FSM.

mod active;
mod error;
mod fsm;
mod handshaking;
mod pre_handshake;

#[cfg(test)]
pub(super) mod test_helpers;

pub(super) use super::traits::ServerMessageDelegate;
pub(super) use active::Active;
pub(super) use error::Error;
pub(super) use fsm::*;
pub(super) use handshaking::Handshaking;
pub(super) use pre_handshake::PreHandshake;
