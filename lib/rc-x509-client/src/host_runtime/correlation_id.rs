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

use std::fmt::Display;

/// An identifier that uniquely identifies messages and their expected response.
///
/// A [`CorrelationId`] provides no guarantees other than being unique per
/// connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct CorrelationId(u64);

impl CorrelationId {
    /// Wrap `v` as a [`CorrelationId`].
    pub fn new(v: u64) -> Self {
        Self(v)
    }

    /// Return the raw `u64` value.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        let c = CorrelationId::new(42);
        assert_eq!(c.to_string(), "42");
    }
}
