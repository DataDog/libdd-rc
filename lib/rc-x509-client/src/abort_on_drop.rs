use tokio::task::JoinHandle;

/// A [`JoinHandle`] wrapper that ensures the task is aborted when the handle
/// goes out of scope.
///
/// The inner handle can be obtained, defusing the abort-on-drop, using the
/// [`AbortOnDrop::into_inner()`] call.
#[must_use = "AbortOnDrop immediately aborts the task if not held in scope"]
#[derive(Debug)]
pub(crate) struct AbortOnDrop<T>(Option<JoinHandle<T>>);

impl<T> AbortOnDrop<T> {
    pub(crate) fn into_inner(mut self) -> JoinHandle<T> {
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
    use assert_matches::assert_matches;
    use tokio::sync::{mpsc, oneshot};

    use super::*;

    #[tokio::test]
    async fn test_abort() {
        let (tx, mut rx) = mpsc::channel(2);

        let handle = AbortOnDrop::from(tokio::spawn(async move {
            // Signal the main task to abort.
            tx.send(()).await.unwrap();

            todo!()
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
