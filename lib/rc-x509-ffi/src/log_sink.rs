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

use std::ffi::c_int;
use std::sync::OnceLock;

use tracing::level_filters::LevelFilter;

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

    /// The requested `level` is not one of the values documented on
    /// [`rc_enable_log_sink()`]. `fd` was not touched and remains owned by
    /// the caller.
    InvalidLevel = 2,

    /// Log sinks are not supported on this platform. `fd` was not touched
    /// and remains owned by the caller.
    Unsupported = i32::MAX,
}

/// Tracks whether a global `tracing` subscriber has already been installed by
/// a prior call to [`rc_enable_log_sink()`], so repeat calls can be rejected
/// rather than panicking (the `tracing` crate only supports one global
/// subscriber per process).
static LOG_SINK_INSTALLED: OnceLock<()> = OnceLock::new();

/// Install `fd` as a sink for `tracing` events emitted by the client library,
/// at the given verbosity `level`:
///
///   * `0`: off (no events).
///   * `1`: error.
///   * `2`: warn.
///   * `3`: info.
///   * `4`: debug.
///   * `5`: trace.
///
/// This is intended for local debugging and example hosts, not production
/// use: every matching `tracing` event is formatted and written to `fd` with
/// a blocking write, so a slow or non-draining reader on the other end of
/// `fd` (e.g. an unread pipe) stalls whichever thread produced the event.
///
/// Only the first call to this function during the lifetime of the process
/// takes effect, per the single-global-subscriber limitation described
/// above; see [`LogSinkRet`] for how repeat or invalid calls are reported.
///
///   * Called by: `host runtime`.
///   * Ownership: passes ownership of `fd` to the client library if and only
///     if [`LogSinkRet::Success`] is returned; the caller retains ownership
///     of `fd` for every other return value.
///
/// # Safety
///
/// `fd` MUST be a valid, open, writable file descriptor that the caller does
/// not use or close after a [`LogSinkRet::Success`] return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_enable_log_sink(fd: c_int, level: c_int) -> LogSinkRet {
    let Some(max_level) = level_filter_from_raw(level) else {
        return LogSinkRet::InvalidLevel;
    };

    unsafe { imp::enable_log_sink(fd, max_level) }
}

fn level_filter_from_raw(level: c_int) -> Option<LevelFilter> {
    match level {
        0 => Some(LevelFilter::OFF),
        1 => Some(LevelFilter::ERROR),
        2 => Some(LevelFilter::WARN),
        3 => Some(LevelFilter::INFO),
        4 => Some(LevelFilter::DEBUG),
        5 => Some(LevelFilter::TRACE),
        _ => None,
    }
}

#[cfg(unix)]
mod imp {
    use std::fs::File;
    use std::os::fd::FromRawFd;

    use tracing::level_filters::LevelFilter;

    use super::{LOG_SINK_INSTALLED, LogSinkRet};

    /// # Safety
    ///
    /// See [`super::rc_enable_log_sink()`].
    pub(super) unsafe fn enable_log_sink(
        fd: std::ffi::c_int,
        max_level: LevelFilter,
    ) -> LogSinkRet {
        if LOG_SINK_INSTALLED.set(()).is_err() {
            return LogSinkRet::AlreadySet;
        }

        // SAFETY: the caller contract requires `fd` to be a valid, open,
        // writable descriptor whose ownership is transferred to us on the
        // success path we're now committed to.
        let file = unsafe { File::from_raw_fd(fd) };

        let subscriber = tracing_subscriber::fmt()
            .with_max_level(max_level)
            .with_writer(move || file.try_clone().expect("duplicate log sink fd"))
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .expect("no global tracing subscriber installed prior to rc_enable_log_sink");

        LogSinkRet::Success
    }
}

#[cfg(not(unix))]
mod imp {
    use tracing::level_filters::LevelFilter;

    use super::LogSinkRet;

    pub(super) unsafe fn enable_log_sink(
        _fd: std::ffi::c_int,
        _max_level: LevelFilter,
    ) -> LogSinkRet {
        LogSinkRet::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::IntoRawFd;

    use super::*;

    /// Exercises the full [`rc_enable_log_sink()`] contract in a single test:
    /// invalid levels are rejected up front, a valid install makes a
    /// subsequent `tracing` event observable on the other end of the pipe,
    /// and a repeat install is rejected. This has to be one test rather than
    /// several, since `LOG_SINK_INSTALLED` is a process-global static that
    /// would otherwise race across parallel test threads.
    #[test]
    fn test_log_sink_lifecycle() {
        let (_reader, writer) = std::io::pipe().expect("create pipe");
        let ret = unsafe { rc_enable_log_sink(writer.into_raw_fd(), 42) };
        assert_eq!(ret, LogSinkRet::InvalidLevel);

        let (mut reader, writer) = std::io::pipe().expect("create pipe");
        let ret = unsafe { rc_enable_log_sink(writer.into_raw_fd(), 5) };
        assert_eq!(ret, LogSinkRet::Success);

        tracing::error!("hello from the log sink test");

        let mut buf = [0u8; 4096];
        let n = reader.read(&mut buf).expect("read from pipe");
        let line = String::from_utf8_lossy(&buf[..n]);
        assert!(line.contains("hello from the log sink test"), "{line}");

        let (_reader, writer) = std::io::pipe().expect("create pipe");
        let ret = unsafe { rc_enable_log_sink(writer.into_raw_fd(), 5) };
        assert_eq!(ret, LogSinkRet::AlreadySet);
    }
}
