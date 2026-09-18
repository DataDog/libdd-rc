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

//! FFI function allowing a host to capture [`tracing`] output emitted by the
//! client library, for local debugging.

use std::{ffi::c_int, sync::atomic::AtomicBool};

/// Result of a [`rc_enable_log_sink()`] call.
#[derive(Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum LogSinkRet {
    /// The log sink was installed successfully; ownership of `fd` has passed
    /// to the client library.
    Success = 0,

    /// A log sink has already been installed for this process; only the
    /// first call to [`rc_enable_log_sink()`] can take effect. `fd` was not
    /// touched and remains owned by the caller.
    AlreadySet = 1,

    /// Log sinks are not supported on this platform. `fd` was not touched
    /// and remains owned by the caller.
    Unsupported = i32::MAX,
}

/// Tracks whether a global `tracing` subscriber has already been installed by
/// a prior call to [`rc_enable_log_sink()`], so repeat calls can be rejected
/// rather than panicking (the `tracing` crate only supports one global
/// subscriber per process).
static LOG_SINK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install `fd` as a sink for `tracing` events emitted by the client library.
///
/// Callers MUST NOT cause writes to this `fd` to block (e.g. by not reading a
/// fixed size pipe).
///
/// The value of the env var `RC_LOG` at the time of this call sets the log
/// level (e.g. `RC_LOG=debug`), defaulting to `info`.
///
/// Only the first call to this function during the lifetime of the process
/// takes effect; see [`LogSinkRet`] for how repeat or invalid calls are
/// reported.
///
///   * Called by: `host runtime`.
///   * Ownership: passes ownership of `fd` to the client library if and only if
///     [`LogSinkRet::Success`] is returned; the caller retains ownership of
///     `fd` for every other return value.
///
/// # Safety
///
/// `fd` MUST be a valid, open, writeable file descriptor that the caller does
/// not use or close after a [`LogSinkRet::Success`] return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_enable_log_sink(fd: c_int) -> LogSinkRet {
    unsafe { imp::enable_log_sink(fd) }
}

mod imp {
    use std::{fs::File, sync::atomic::Ordering};

    use tracing_subscriber::{EnvFilter, layer::SubscriberExt};

    use super::{LOG_SINK_INSTALLED, LogSinkRet};

    /// # Safety
    ///
    /// See [`super::rc_enable_log_sink()`].
    pub(super) unsafe fn enable_log_sink(fd: std::ffi::c_int) -> LogSinkRet {
        if LOG_SINK_INSTALLED
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return LogSinkRet::AlreadySet;
        }

        // SAFETY: the caller contract requires `fd` to be a valid, open,
        // writeable descriptor whose ownership is transferred to us on the
        // success path we're now committed to.
        //
        // Perform this prior to dispatching to the cfg-gated
        // install_subscriber() so that miri can check the unsafe call here.
        let file = unsafe { raw_to_file(fd) };

        install_subscriber(file);

        LogSinkRet::Success
    }

    #[cfg(not(miri))]
    fn install_subscriber(f: File) {
        let file = std::sync::Mutex::new(std::io::LineWriter::new(f));

        let fmt_layer = tracing_subscriber::fmt::layer().with_writer(file);

        let env_filter =
            EnvFilter::try_from_env("RC_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

        let subscriber = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer);

        tracing::subscriber::set_global_default(subscriber)
            .expect("no global tracing subscriber installed prior to rc_enable_log_sink");
    }

    #[cfg(miri)]
    fn install_subscriber(mut f: File) {
        use std::io::Write;

        // Silence "unused dependency" lint.
        use tracing_subscriber as _;

        // Mimic doing log stuff.
        let _ = writeln!(f, "it's bananas");
        let _ = writeln!(f, "it's still bananas");
    }

    #[cfg(unix)]
    unsafe fn raw_to_file(fd: std::ffi::c_int) -> File {
        use std::os::fd::FromRawFd;
        unsafe { File::from_raw_fd(fd) }
    }

    #[cfg(windows)]
    unsafe fn raw_to_file(fd: std::ffi::c_int) -> File {
        use std::os::windows::io::{FromRawHandle, RawHandle};
        let raw_handle: RawHandle = (fd as isize) as RawHandle;
        unsafe { File::from_raw_handle(raw_handle) }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::IntoRawFd;

    use super::*;

    /// Exercises the full [`rc_enable_log_sink()`] contract in a single test
    /// (only the first call in a process takes effect, so this can't be
    /// split across multiple `#[test]` fns): `RC_LOG` set before the call
    /// governs the installed filter level, a valid install makes subsequent
    /// `tracing` events at or above that level observable on the other end
    /// of the pipe while events below it are dropped, and a repeat install
    /// is rejected.
    #[test]
    fn test_log_sink_lifecycle() {
        // SAFETY: no other threads read/write env vars concurrently in this
        // test binary.
        unsafe { std::env::set_var("RC_LOG", "debug") };

        let (mut reader, writer) = std::io::pipe().expect("create pipe");
        let ret = unsafe { rc_enable_log_sink(writer.into_raw_fd()) };
        assert_eq!(ret, LogSinkRet::Success);

        tracing::error!("it's bananas");
        tracing::debug!("it's still bananas");
        tracing::trace!("it's not bananas");

        let mut buf = [0u8; 4096];
        let n = reader.read(&mut buf).expect("read from pipe");
        let line = String::from_utf8_lossy(&buf[..n]);
        assert!(line.contains("it's bananas"), "{line}");
        assert!(line.contains("it's still bananas"), "{line}");
        assert!(
            !line.contains("it's not bananas"),
            "RC_LOG=debug should not enable trace-level events: {line}"
        );

        let (_reader, writer) = std::io::pipe().expect("create pipe");
        let ret = unsafe { rc_enable_log_sink(writer.into_raw_fd()) };
        assert_eq!(ret, LogSinkRet::AlreadySet);
    }
}
