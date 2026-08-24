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

use tokio_util::sync::CancellationToken;

/// An asynchronous signal to stop all work and clean up all resources held
/// before the library runtime exits.
///
/// [`ShutdownSignal`] observes the shutdown of a client library instance,
/// triggered from a single [`ShutdownCtl`].
///
/// This is not a general purpose cancellation primitive; it should be used
/// specifically for graceful shutdown of client library instances.
#[derive(Debug, Clone)]
pub struct ShutdownSignal(CancellationToken);

impl ShutdownSignal {
    /// Construct a new [`ShutdownSignal`].
    pub fn new() -> (Self, ShutdownCtl) {
        let token = CancellationToken::new();
        (Self(token.clone()), ShutdownCtl(token))
    }

    /// Return a [`CancellationToken`] that is cancelled when this
    /// [`ShutdownSignal`] is signalled, but can also be cancelled within the
    /// scope of the returned [`CancellationToken`] independently of this
    /// [`ShutdownSignal`].
    pub fn child_token(&self) -> CancellationToken {
        self.0.child_token()
    }

    /// Wait for the shutdown signal.
    pub async fn wait_for_shutdown(&self) {
        self.0.cancelled().await
    }
}

/// A handle to initiate a graceful shutdown of all workers consuming the
/// [`ShutdownSignal`] this type controls.
#[derive(Debug)]
pub struct ShutdownCtl(CancellationToken);

impl ShutdownCtl {
    /// Wait for the shutdown signal.
    pub fn shutdown_now(self) {
        self.0.cancel();
    }

    /// Obtain a new [`ShutdownSignal`] tied to this [`ShutdownCtl`].
    pub fn get_signal(&self) -> ShutdownSignal {
        ShutdownSignal(self.0.clone())
    }
}

impl Drop for ShutdownCtl {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::{join, sync::mpsc};

    use super::*;

    /// The [`ShutdownCtl`] holder explicitly calls
    /// [`ShutdownCtl::shutdown_now()`].
    #[tokio::test]
    async fn test_explicit_shutdown() {
        let (signal, ctl) = ShutdownSignal::new();

        // Indicators that the spawned functions have initialised and are
        // waiting for shutdown.
        let (tx, mut rx) = mpsc::channel::<()>(1);

        let a = tokio::spawn({
            let signal = signal.clone();
            let tx = tx.clone();
            async move {
                drop(tx);
                signal.wait_for_shutdown().await;
            }
        });

        let b = tokio::spawn({
            async move {
                drop(tx);
                signal.wait_for_shutdown().await;

                // Idempotent: once cancelled, it always returns immediately.
                signal.wait_for_shutdown().await;
                signal.wait_for_shutdown().await;
                signal.wait_for_shutdown().await;
            }
        });

        // Wait for the workers to spawn and drop their signal handles.
        //
        // This call completes (with an error) once all tx handles are dropped.
        let _ = rx.recv().await;

        // Stall this async task for a while, to ensure the scheduler will give
        // runtime to the others, letting them quit if the shutdown signal is
        // broken.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Ensure both tasks are running.
        assert!(!a.is_finished());
        assert!(!b.is_finished());

        // Signal the workers to shutdown.
        ctl.shutdown_now();

        // Wait for both tasks to stop.
        let (a, b) = tokio::time::timeout(Duration::from_secs(5), async { join!(a, b) })
            .await
            .expect("timeout waiting for worker tasks to stop");

        // Worker tasks should not have panicked.
        assert!(a.is_ok());
        assert!(b.is_ok());
    }

    /// The [`ShutdownCtl`] holder drops the handle without explicitly calling
    /// [`ShutdownCtl::shutdown_now()`].
    #[tokio::test]
    async fn test_implicit_shutdown() {
        let (signal, ctl) = ShutdownSignal::new();

        // Indicators that the spawned functions have initialised and are
        // waiting for shutdown.
        let (tx, mut rx) = mpsc::channel::<()>(1);

        let a = tokio::spawn({
            let signal = signal.clone();
            let tx = tx.clone();
            async move {
                drop(tx);
                signal.wait_for_shutdown().await;
            }
        });

        let b = tokio::spawn({
            async move {
                drop(tx);
                signal.wait_for_shutdown().await;

                // Idempotent: once cancelled, it always returns immediately.
                signal.wait_for_shutdown().await;
                signal.wait_for_shutdown().await;
                signal.wait_for_shutdown().await;
            }
        });

        // Wait for the workers to spawn and drop their signal handles.
        //
        // This call completes (with an error) once all tx handles are dropped.
        let _ = rx.recv().await;

        // Stall this async task for a while, to ensure the scheduler will give
        // runtime to the others, letting them quit if the shutdown signal is
        // broken.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Ensure both tasks are running.
        assert!(!a.is_finished());
        assert!(!b.is_finished());

        // Implicitly signal the workers should stop due to the ctl handle going
        // out of scope.
        drop(ctl);

        // Wait for both tasks to stop.
        let (a, b) = tokio::time::timeout(Duration::from_secs(5), async { join!(a, b) })
            .await
            .expect("timeout waiting for worker tasks to stop");

        // Worker tasks should not have panicked.
        assert!(a.is_ok());
        assert!(b.is_ok());
    }

    #[test]
    fn test_child_token() {
        let (signal, shutdown) = ShutdownSignal::new();

        let child_a = signal.child_token();
        let child_b = signal.child_token();

        assert!(!child_a.is_cancelled());
        assert!(!child_b.is_cancelled());

        // Cancelling one child works:
        child_a.cancel();
        assert!(child_a.is_cancelled());

        // Does not affect child B or the shutdown signal:
        assert!(!child_b.is_cancelled());
        assert!(!signal.0.is_cancelled());

        // But cancelling the shutdown token cancels all children:
        shutdown.shutdown_now();
        assert!(child_b.is_cancelled());
        assert!(signal.0.is_cancelled());
    }
}
