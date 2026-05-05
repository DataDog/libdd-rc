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

//! A helper type that caches a [`String`] representation of a parent type, and
//! implements commonly derived helper traits.

use std::{
    cmp::Ordering,
    sync::{Arc, OnceLock},
};

/// A cached [`String`] representation for a parent value.
#[derive(Debug, Default, Clone)]
pub(crate) struct CachedStringRepr(OnceLock<Arc<str>>);

impl CachedStringRepr {
    pub(crate) fn get_or_init<F>(&self, f: F) -> &Arc<str>
    where
        F: FnOnce() -> String,
    {
        self.0.get_or_init(|| Arc::from(f()))
    }
}

// Impls all the things in a state insensitive way, so parent types can derive
// them:

impl PartialEq for CachedStringRepr {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}
impl Eq for CachedStringRepr {}
impl std::hash::Hash for CachedStringRepr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        42_u8.hash(state)
    }
}
impl PartialOrd for CachedStringRepr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for CachedStringRepr {
    fn cmp(&self, _other: &Self) -> Ordering {
        Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hasher};

    use super::*;

    fn do_hash<T: std::hash::Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    #[test]
    fn test_properties() {
        let a = CachedStringRepr::default();
        let b = CachedStringRepr::default();

        assert_eq!(a, b);
        assert_eq!(do_hash(&a), do_hash(&b));

        // Drive the population of the cached rendered repr.
        let _ = b.get_or_init(|| "bananas".to_string());

        assert_eq!(a, b);
        assert_eq!(do_hash(&a), do_hash(&b));
    }
}
