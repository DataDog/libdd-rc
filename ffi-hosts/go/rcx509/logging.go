package rcx509

import "github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi"

// LogLevel is the severity of a log event delivered to a LogHandler.
type LogLevel = libddrcffi.LogLevel

// The severities a LogHandler may receive, from least to most verbose.
const (
	LogLevelError = libddrcffi.LogLevelError
	LogLevelWarn  = libddrcffi.LogLevelWarn
	LogLevelInfo  = libddrcffi.LogLevelInfo
	LogLevelDebug = libddrcffi.LogLevelDebug
	LogLevelTrace = libddrcffi.LogLevelTrace
)

// LogHandler receives log events emitted by the underlying Rust client
// library, once registered with SetLogHandler.
//
// It MUST NOT block, and MUST be safe to call concurrently: it may be
// invoked from any goroutine driving the underlying library, at any time
// after SetLogHandler returns.
type LogHandler = libddrcffi.LogHandler

// SetLogHandler registers handler to receive log events emitted by the
// underlying Rust client library, at minLevel or more severe.
//
// This is entirely opt-in and process-wide, not tied to any single Client:
// applications that do not need visibility into the library's internal logs
// do not need to call this at all. If called, it must be called at most once
// per process, and before the first call to NewClient.
func SetLogHandler(handler LogHandler, minLevel LogLevel) error {
	return libddrcffi.SetLogHandler(handler, minLevel)
}
