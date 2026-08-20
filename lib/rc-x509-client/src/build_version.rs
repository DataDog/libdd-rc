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

/// Client build version information for the currently running instance.
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct BuildVersion {
    #[cfg_attr(test, proptest(value = r#"env!("BUILD_GIT_COMMIT_HASH")"#))]
    commit: &'static str,

    major: u32,
    minor: u32,
    patch: u32,

    #[cfg_attr(test, proptest(value = r#"None"#))]
    pre: Option<&'static str>,
}

impl BuildVersion {
    /// Return the major semver value.
    pub(crate) fn major(&self) -> u32 {
        self.major
    }

    /// Return the minor semver value.
    pub(crate) fn minor(&self) -> u32 {
        self.minor
    }

    /// Return the patch semver value.
    pub(crate) fn patch(&self) -> u32 {
        self.patch
    }

    /// Return the pre-release string value.
    pub(crate) fn pre(&self) -> Option<&str> {
        self.pre
    }

    /// Return the Git commit hash of the build.
    pub(crate) fn commit(&self) -> &'static str {
        self.commit
    }

    /// Obtain a [`BuildVersion`] that describes the currently running build.
    pub(crate) fn from_build() -> Self {
        let pre = match env!("CARGO_PKG_VERSION_PRE") {
            "" => None,
            v => Some(v),
        };

        Self {
            major: env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap(),
            minor: env!("CARGO_PKG_VERSION_MINOR").parse().unwrap(),
            patch: env!("CARGO_PKG_VERSION_PATCH").parse().unwrap(),
            pre,
            commit: env!("BUILD_GIT_COMMIT_HASH"),
        }
    }
}

impl Default for BuildVersion {
    fn default() -> Self {
        Self::from_build()
    }
}

impl Display for BuildVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.pre {
            Some(pre) => {
                write!(
                    f,
                    "{major}.{minor}.{patch}-{pre} ({hash})",
                    major = self.major(),
                    minor = self.minor(),
                    patch = self.patch(),
                    hash = self.commit()
                )
            }
            None => {
                write!(
                    f,
                    "{major}.{minor}.{patch} ({hash})",
                    major = self.major(),
                    minor = self.minor(),
                    patch = self.patch(),
                    hash = self.commit()
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanity() {
        let v = BuildVersion::from_build();
        assert_eq!(v.major(), env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap());
        assert_eq!(v.minor(), env!("CARGO_PKG_VERSION_MINOR").parse().unwrap());
        assert_eq!(v.patch(), env!("CARGO_PKG_VERSION_PATCH").parse().unwrap());
        assert_eq!(v.pre().unwrap_or_default(), env!("CARGO_PKG_VERSION_PRE"));

        assert_eq!(v.commit().len(), 40);
    }

    #[test]
    fn test_display_with_pre() {
        let v = BuildVersion {
            commit: "c97b3db69056405b8116dc94d8033a4cb335fe9e",
            major: 4,
            minor: 2,
            patch: 0,
            pre: Some("alpha"),
        };

        assert_eq!(
            v.to_string(),
            "4.2.0-alpha (c97b3db69056405b8116dc94d8033a4cb335fe9e)"
        );
    }

    #[test]
    fn test_display() {
        let v = BuildVersion {
            commit: "c97b3db69056405b8116dc94d8033a4cb335fe9e",
            major: 4,
            minor: 2,
            patch: 0,
            pre: None,
        };

        assert_eq!(
            v.to_string(),
            "4.2.0 (c97b3db69056405b8116dc94d8033a4cb335fe9e)"
        );
    }
}
