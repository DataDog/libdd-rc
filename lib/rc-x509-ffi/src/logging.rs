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

//! An opt-in bridge that forwards this library's internal [`tracing`] events
//! to a FFI host that cannot otherwise install a [`tracing::Subscriber`] of
//! its own (a Rust host embedding this crate directly does not need this: it
//! already controls the global subscriber and will observe these events
//! without any FFI call).

use std::ffi::c_void;

use tracing::field::{Field, Visit};
use tracing::span;
use tracing::{Event, Level, Metadata, Subscriber};

/// The severity of a log event forwarded through [`LogCb`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum LogLevel {
    /// Unrecoverable or unexpected error conditions.
    Error = 0,
    /// Recoverable but noteworthy conditions.
    Warn = 1,
    /// High level, infrequent operational messages.
    Info = 2,
    /// Detailed diagnostic messages, useful when troubleshooting.
    Debug = 3,
    /// Very high frequency, fine-grained tracing messages.
    Trace = 4,
}

impl From<LogLevel> for Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => Level::ERROR,
            LogLevel::Warn => Level::WARN,
            LogLevel::Info => Level::INFO,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Trace => Level::TRACE,
        }
    }
}

fn level_from_tracing(level: &Level) -> LogLevel {
    match *level {
        Level::ERROR => LogLevel::Error,
        Level::WARN => LogLevel::Warn,
        Level::INFO => LogLevel::Info,
        Level::DEBUG => LogLevel::Debug,
        Level::TRACE => LogLevel::Trace,
    }
}

/// The callback invoked for each log event emitted by this library, once
/// registered via [`rc_set_log_callback()`].
///
/// `target` and `message` point to UTF-8 byte slices of `target_len` and
/// `message_len` bytes respectively, valid only for the duration of this
/// call. `message` carries only the formatted `message` field of the event;
/// any other structured fields attached to the event are not forwarded.
///
/// The callback MUST NOT block, which stalls whichever thread emitted the log
/// event. The callback MUST NOT panic, and MUST be safe to call concurrently
/// from multiple threads: log events may be emitted from any thread in the
/// process, at any time after registration.
///
///   * Called by: `client library`.
///   * Ownership: passes shared references to the `target` and `message`
///     arrays to the host runtime for the duration of the call.
pub type LogCb = unsafe extern "C" fn(
    level: LogLevel,
    target: *const u8,
    target_len: u32,
    message: *const u8,
    message_len: u32,
    user_data: *const c_void,
);

/// A container to hold the callback context pointer for a [`LogCb`] call.
///
/// NOTE: the pointer MAY be null and MUST never be dereferenced or modified.
#[derive(Debug, Clone, Copy)]
struct LogCbUserData(*const c_void);

/// Safety: the FFI caller guarantees this pointer can be sent and shared
/// between threads. This pointer is never dereferenced by this library.
unsafe impl Send for LogCbUserData {}
unsafe impl Sync for LogCbUserData {}

/// A [`tracing::Subscriber`] that forwards every event at or above
/// `min_level` to a [`LogCb`]. Spans are not tracked: this bridge only
/// forwards individual log events.
struct FfiLogSubscriber {
    callback: LogCb,
    user_data: LogCbUserData,
    min_level: Level,
}

/// Collects the formatted `message` field of an event, ignoring any other
/// structured fields.
#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write;
            let _ = write!(self.message, "{value:?}");
        }
    }
}

impl Subscriber for FfiLogSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= self.min_level
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let metadata = event.metadata();

        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let level = level_from_tracing(metadata.level());
        let target = metadata.target().as_bytes();
        let message = visitor.message.as_bytes();

        unsafe {
            (self.callback)(
                level,
                target.as_ptr(),
                target.len() as u32,
                message.as_ptr(),
                message.len() as u32,
                self.user_data.0,
            );
        }
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

/// Register a callback to receive this library's internal log events, for FFI
/// hosts that have no other way to observe them.
///
/// This is entirely opt-in: a host that never calls this function sees no
/// change in behaviour (log events are emitted via [`tracing`] and dropped, as
/// they are today). A Rust host embedding this crate directly does not need
/// this either, and should install its own [`tracing::Subscriber`] instead.
///
/// Returns `true` if `callback` was successfully installed, or `false` if a
/// global [`tracing::Subscriber`] was already installed elsewhere in this
/// process (including by a previous call to this function).
///
///   * Called by: `host runtime`.
///   * Ownership: retains no ownership; `user_data` is passed back to
///     `callback` for the lifetime of the process.
///
/// # Safety
///
/// This call MUST be made at most once per process, before any other call
/// into this library, and MUST provide a `callback` that is valid and safe to
/// call concurrently at all times thereafter, for the lifetime of the
/// process. The `user_data` pointer MAY be null, but MUST be safe to share
/// between threads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_set_log_callback(
    callback: LogCb,
    min_level: LogLevel,
    user_data: *const c_void,
) -> bool {
    let subscriber = FfiLogSubscriber {
        callback,
        user_data: LogCbUserData(user_data),
        min_level: min_level.into(),
    };

    tracing::subscriber::set_global_default(subscriber).is_ok()
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Debug, Default, Clone, PartialEq)]
    struct Recorded {
        level: Option<LogLevel>,
        target: String,
        message: String,
    }

    unsafe extern "C" fn record_cb(
        level: LogLevel,
        target: *const u8,
        target_len: u32,
        message: *const u8,
        message_len: u32,
        user_data: *const c_void,
    ) {
        let recorder = unsafe { &*(user_data as *const Mutex<Vec<Recorded>>) };
        let target = String::from_utf8_lossy(unsafe {
            std::slice::from_raw_parts(target, target_len as usize)
        })
        .into_owned();
        let message = String::from_utf8_lossy(unsafe {
            std::slice::from_raw_parts(message, message_len as usize)
        })
        .into_owned();

        recorder.lock().unwrap().push(Recorded {
            level: Some(level),
            target,
            message,
        });
    }

    /// Registering a log callback captures events emitted at or above the
    /// configured minimum level, and filters out events below it.
    #[test]
    fn test_log_callback_forwards_and_filters_events() {
        let recorder: Arc<Mutex<Vec<Recorded>>> = Arc::new(Mutex::new(Vec::new()));
        let subscriber = FfiLogSubscriber {
            callback: record_cb,
            user_data: LogCbUserData(Arc::as_ptr(&recorder) as *const c_void),
            min_level: Level::INFO,
        };

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("hello {}", "world");
            tracing::debug!("should be filtered out");
        });

        let recorded = recorder.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].level, Some(LogLevel::Info));
        assert_eq!(recorded[0].message, "hello world");
    }
}
