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

//! The host tags ("key:value" strings) a host application reports for this
//! client, used by the backend for RPC targeting.

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::Arc,
};

use tokio::sync::watch;

/// The latest normalised set of host tags, and its fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostTags {
    tags: Arc<[String]>,
    fingerprint: u64,
}

impl Default for HostTags {
    fn default() -> Self {
        Self::new(std::iter::empty::<&str>())
    }
}

impl HostTags {
    /// Normalises tags: empty and duplicate strings are dropped,
    /// values are then sorted.
    fn new(tags: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        let mut tags: Vec<String> = tags
            .into_iter()
            .map(|v| v.as_ref().to_owned())
            .filter(|v| !v.is_empty())
            .collect();
        tags.sort_unstable();
        tags.dedup();

        let mut hasher = DefaultHasher::new();
        tags.hash(&mut hasher);

        Self {
            tags: tags.into(),
            fingerprint: hasher.finish(),
        }
    }

    pub(crate) fn tags(&self) -> &[String] {
        &self.tags
    }

    pub(crate) fn fingerprint(&self) -> u64 {
        self.fingerprint
    }
}

/// Replaces the host tags reported by an `rc-x509-client` instance.
///
/// The latest set is kept and reported, receivers are notified when
/// the normalised set changes.
#[derive(Debug, Clone)]
pub struct HostTagsSetter(Arc<watch::Sender<HostTags>>);

impl HostTagsSetter {
    /// Replace the full set of host tags.
    pub fn set(&self, tags: impl IntoIterator<Item = impl AsRef<str>>) {
        let new = HostTags::new(tags);
        self.0.send_if_modified(|current| {
            if current.fingerprint == new.fingerprint {
                return false;
            }
            *current = new;
            true
        });
    }
}

/// Observes the host tags set through the [`HostTagsSetter`] it was created
/// with, starting out empty.
#[derive(Debug, Clone)]
pub(crate) struct HostTagsWatch(watch::Receiver<HostTags>);

impl HostTagsWatch {
    /// Construct a new [`HostTagsWatch`] and the [`HostTagsSetter`] that
    /// updates it.
    pub(crate) fn new() -> (Self, HostTagsSetter) {
        let (tx, rx) = watch::channel(HostTags::default());
        (Self(rx), HostTagsSetter(Arc::new(tx)))
    }

    /// Wait for the host tags to change, returning the new set, or [`None`]
    /// once they can no longer change because every [`HostTagsSetter`] has been
    /// dropped.
    pub(crate) async fn next_change(&mut self) -> Option<HostTags> {
        self.0.changed().await.ok()?;
        Some(self.latest())
    }

    /// The latest host tags, marking them as seen by [`Self::next_change()`].
    pub(crate) fn latest(&mut self) -> HostTags {
        self.0.borrow_and_update().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalise() {
        let got = HostTags::new(["env:prod", "", "app:web", "env:prod", "env:staging"]);
        assert_eq!(got.tags(), ["app:web", "env:prod", "env:staging"]);
    }

    #[test]
    fn test_fingerprint_ignores_order_and_duplicates() {
        let a = HostTags::new(["env:prod", "host:a"]);
        let b = HostTags::new(["host:a", "env:prod", "host:a"]);
        let c = HostTags::new(["env:prod", "host:b"]);

        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_ne!(a.fingerprint(), c.fingerprint());
    }

    #[test]
    fn test_set_only_notifies_on_change() {
        let (mut watch, setter) = HostTagsWatch::new();
        watch.latest();

        setter.set(["env:prod", "host:a"]);
        assert!(watch.0.has_changed().unwrap());
        assert_eq!(watch.latest().tags(), ["env:prod", "host:a"]);

        // The same set, in a different order, with a duplicate.
        setter.set(["host:a", "env:prod", "env:prod"]);
        assert!(!watch.0.has_changed().unwrap());

        setter.set(["env:prod", "host:b"]);
        assert!(watch.0.has_changed().unwrap());
        assert_eq!(watch.latest().tags(), ["env:prod", "host:b"]);
    }

    #[test]
    fn test_late_watch_sees_latest_set() {
        // A clone taken after the tags were set sees the
        // latest set.
        let (watch, setter) = HostTagsWatch::new();
        setter.set(["env:prod"]);

        let mut late = watch.clone();
        assert_eq!(late.latest().tags(), ["env:prod"]);
    }

    #[tokio::test]
    async fn test_next_change_returns_new_set() {
        let (mut watch, setter) = HostTagsWatch::new();
        setter.set(["env:prod"]);

        let tags = watch.next_change().await.expect("setter is alive");
        assert_eq!(tags.tags(), ["env:prod"]);
    }

    #[tokio::test]
    async fn test_next_change_ends_once_setter_dropped() {
        let (mut watch, setter) = HostTagsWatch::new();
        drop(setter);
        assert!(watch.next_change().await.is_none());
    }
}
