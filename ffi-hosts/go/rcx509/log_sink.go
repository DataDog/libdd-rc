package rcx509

import (
	"os"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi"
)

// LogLevel selects the verbosity of events written by a log sink installed
// via EnableLogSink.
type LogLevel = libddrcffi.LogLevel

const (
	LogLevelOff   = libddrcffi.LogLevelOff
	LogLevelError = libddrcffi.LogLevelError
	LogLevelWarn  = libddrcffi.LogLevelWarn
	LogLevelInfo  = libddrcffi.LogLevelInfo
	LogLevelDebug = libddrcffi.LogLevelDebug
	LogLevelTrace = libddrcffi.LogLevelTrace
)

// ErrLogSinkAlreadySet is returned by EnableLogSink when a log sink has
// already been installed for this process.
var ErrLogSinkAlreadySet = libddrcffi.ErrLogSinkAlreadySet

// EnableLogSink installs `f“ as the destination for tracing events emitted by
// the underlying client library, at the given level, for local debugging.
//
// Callers must ensure the os.File remains open and reachable to keep the
// underlying file descriptor live throughout the process's lifetime.
func EnableLogSink(level LogLevel, f *os.File) error {
	return libddrcffi.EnableLogSink(f.Fd(), level)
}
