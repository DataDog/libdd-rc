package libddrcffi

/*
#include "libdd_rc.h"

// Forward declaration for the goLogCb function exported from callbacks.go:
// cgo requires this to reference it from another file in the same package.
extern void goLogCb(LogLevel level, uint8_t *target, uint32_t target_len, uint8_t *message, uint32_t message_len, void *user_data);
*/
import "C"

import (
	"errors"
	"sync"
)

// LogLevel mirrors the severity levels of the Rust client library's LogLevel
// enum (see include/libdd_rc.h).
type LogLevel int32

const (
	LogLevelError LogLevel = iota
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

// String returns a lower-case name for the level, or "unknown" for any value
// outside the range defined by LogLevel's constants.
func (l LogLevel) String() string {
	switch l {
	case LogLevelError:
		return "error"
	case LogLevelWarn:
		return "warn"
	case LogLevelInfo:
		return "info"
	case LogLevelDebug:
		return "debug"
	case LogLevelTrace:
		return "trace"
	default:
		return "unknown"
	}
}

// LogHandler receives log events emitted by the underlying Rust client
// library, once registered with SetLogHandler.
//
// It MUST NOT block, and MUST be safe to call concurrently: it may be
// invoked from any goroutine driving the underlying library, at any time
// after SetLogHandler returns.
type LogHandler func(level LogLevel, target, message string)

// ErrLogHandlerAlreadySet is returned by SetLogHandler when a log handler
// has already been installed in this process.
var ErrLogHandlerAlreadySet = errors.New("ddrc: a log handler is already set for this process")

// ErrLogSubscriberAlreadySet is returned by SetLogHandler when the
// underlying library's log subscriber is already installed, other than by a
// previous successful call to SetLogHandler (e.g. a Rust host in the same
// process installed its own tracing subscriber).
var ErrLogSubscriberAlreadySet = errors.New("ddrc: a tracing subscriber is already installed for this process")

var (
	logHandlerMu sync.Mutex
	logHandler   LogHandler
)

// SetLogHandler registers handler to receive log events emitted by the
// underlying Rust client library, at minLevel or more severe.
//
// This is entirely opt-in and process-wide: the underlying library installs
// no logging of its own. Callers that do not need visibility into the
// library's internal logs do not need to call this at all.
//
// SetLogHandler MUST be called at most once per process, and before Init:
// the underlying subscriber cannot be replaced or removed once installed.
func SetLogHandler(handler LogHandler, minLevel LogLevel) error {
	logHandlerMu.Lock()
	defer logHandlerMu.Unlock()

	if logHandler != nil {
		return ErrLogHandlerAlreadySet
	}

	ok := bool(C.rc_set_log_callback(C.LogCb(C.goLogCb), C.LogLevel(minLevel), nil))
	if !ok {
		return ErrLogSubscriberAlreadySet
	}

	logHandler = handler
	return nil
}
