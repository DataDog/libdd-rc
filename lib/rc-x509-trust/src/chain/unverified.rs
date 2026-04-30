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

use std::sync::Arc;

use rc_crypto::certificate::Certificate;

/// An unverified candidate chain for some leaf [`Certificate`]. to some root.
///
/// This type contains the chain of intermediates only.
///
/// An [`UntrustedChain`] is not yet cryptographically verified and must not be
/// trusted.
///
/// ## Chain Value
///
/// This type holds a partial path from a leaf [`Certificate`] to a root, but
/// includes neither:
///
/// ```text
///                 <leaf> -> [SubCA 2, SubCA 1] -> <root>
/// ```
///
/// Where `<leaf>` and `<root>` are implicit / not retained within the
/// [`UntrustedChain`] and must be provided alongside it for any trust
/// operations.
#[derive(Debug)]
pub(crate) struct UntrustedChain(Vec<Arc<Certificate>>);

impl UntrustedChain {
    /// Borrow the chain content.
    pub(crate) fn as_slice(&self) -> &[Arc<Certificate>] {
        &self.0
    }
}

impl From<Vec<Arc<Certificate>>> for UntrustedChain {
    fn from(value: Vec<Arc<Certificate>>) -> Self {
        Self(value)
    }
}
