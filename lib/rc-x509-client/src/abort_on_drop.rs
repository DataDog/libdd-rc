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

use tokio::task::JoinHandle;

/// A [`JoinHandle`] wrapper that ensures the task is aborted when the handle
/// goes out of scope.
///
/// The inner handle can be obtained, defusing the abort-on-drop, using the
/// [`AbortOnDrop::into_inner()`] call.
#[must_use = "AbortOnDrop immediately aborts the task if not held in scope"]
#[derive(Debug)]
pub struct AbortOnDrop<T>(Option<JoinHandle<T>>);

impl<T> AbortOnDrop<T> {
    /// Disarm the abort-on-drop behaviour, returning the [`JoinHandle`] it was
    /// managing.
    pub fn into_inner(mut self) -> JoinHandle<T> {
        self.0.take().expect("must contain task")
    }
}

impl<T> From<JoinHandle<T>> for AbortOnDrop<T> {
    fn from(value: JoinHandle<T>) -> Self {
        Self(Some(value))
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use assert_matches::assert_matches;
    use tokio::sync::{mpsc, oneshot};

    use super::*;

    #[tokio::test]
    async fn test_abort() {
        let (tx, mut rx) = mpsc::channel(2);

        let handle = AbortOnDrop::from(tokio::spawn(async move {
            // Signal the main task to abort.
            tx.send(()).await.unwrap();

            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }));

        rx.recv().await.expect("task is running");
        drop(handle);

        // The next read should fail, as the task has been aborted by dropping
        // the handle.
        assert_matches!(rx.recv().await, None);
    }

    #[tokio::test]
    async fn test_unwrap_handle() {
        let handle = AbortOnDrop::from(tokio::spawn(async move { 42 }));

        let got = handle.into_inner().await.expect("task gracefully returns");
        assert_eq!(got, 42);
    }
}
