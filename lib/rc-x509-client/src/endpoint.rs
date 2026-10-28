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

use std::{fmt::Display, sync::Arc};

/// A reference-counted DNS address of the Datadog datacenter the host
/// application is connected to, as provided by the host application (e.g.
/// `config.datadoghq.com`).
///
/// This value is used during chain validation to enforce the DNS pins (if any)
/// present in the X509 certificates (as named constraints for intermediate
/// certificates, or SAN entries for signing certificates) and must match
/// exactly with at least one SAN in the signing certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct EndpointHostname(Arc<str>);

impl<T> From<T> for EndpointHostname
where
    T: Into<Arc<str>>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl Display for EndpointHostname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Cloning an [`EndpointHostname`] preserves the hostname value, and is
        /// refcounted (and the value it returns matches the value it is
        /// initialised with).
        #[test]
        fn prop_endpoint_hostname_clone_preserves_value(hostname in any::<String>()) {
            let got = EndpointHostname::from(hostname.clone());
            assert_eq!(Arc::strong_count(&got.0), 1);

            let cloned = got.clone();
            assert_eq!(cloned.to_string(), hostname);
            assert_eq!(Arc::strong_count(&got.0), 2);
        }
    }
}
