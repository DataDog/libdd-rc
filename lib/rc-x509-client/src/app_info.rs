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

/// A reference-counted string identifier, for and provided by the host
/// application (e.g. the Datadog Agent).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct AppName(Arc<str>);

impl Display for AppName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> From<T> for AppName
where
    T: Into<Arc<str>>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

/// A reference-counted, schemaless string version descriptor, for and provided
/// by the host application (e.g. the Datadog Agent reporting v1.0.0).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct AppVersion(Arc<str>);

impl<T> From<T> for AppVersion
where
    T: Into<Arc<str>>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl Display for AppVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Static metadata describing the host application.
#[derive(Debug, Clone)]
pub(crate) struct AppInfo {
    name: AppName,
    version: AppVersion,
}

impl AppInfo {
    pub(crate) fn new(name: AppName, version: AppVersion) -> Self {
        Self { name, version }
    }

    pub(crate) fn name(&self) -> &AppName {
        &self.name
    }

    #[allow(dead_code)]
    pub(crate) fn version(&self) -> &AppVersion {
        &self.version
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// An [`AppInfo`] exposes the same name/version it was constructed
        /// with, and doesn't care about actual input values - they're
        /// transparent to this client.
        #[test]
        fn prop_app_info_roundtrips(name in any::<String>(), version in any::<String>()) {
            let info = AppInfo::new(AppName::from(name.clone()), AppVersion::from(version.clone()));
            assert_eq!(info.name().to_string(), name);
            assert_eq!(info.version().to_string(), version);
        }

        /// Cloning an [`AppInfo`] preserves the name/version values, and is
        /// refcounted.
        #[test]
        fn prop_app_info_clone_preserves_values(name in any::<String>(), version in any::<String>()) {
            let info = AppInfo::new(AppName::from(name.clone()), AppVersion::from(version.clone()));

            assert_eq!(Arc::strong_count(&info.name.0), 1);
            assert_eq!(Arc::strong_count(&info.version.0), 1);

            let cloned = info.clone();
            assert_eq!(cloned.name().to_string(), name);
            assert_eq!(cloned.version().to_string(), version);

            assert_eq!(Arc::strong_count(&info.name.0), 2);
            assert_eq!(Arc::strong_count(&info.version.0), 2);
        }
    }
}
