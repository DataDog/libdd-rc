package rcx509

import (
	"fmt"
	"io"
	"os"
	"runtime"

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

// EnableLogSink installs w as the destination for tracing events emitted by
// the underlying client library, at the given level, for local debugging.
//
// This is a package-level function rather than a Client method: the
// underlying rc_enable_log_sink call installs a subscriber global to the
// whole process, not scoped to any one Client's rc-x509-client instance, and
// only the first call across the process takes effect (see
// ErrLogSinkAlreadySet).
//
// It creates an OS pipe, hands its write end across the FFI boundary, and
// copies everything the client library writes to the read end into w on a
// background goroutine for the remaining lifetime of the process: since the
// underlying sink cannot be uninstalled once set, there is no way to stop
// that goroutine either.
func EnableLogSink(level LogLevel, w io.Writer) error {
	reader, writer, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("rcx509: failed to create log sink pipe: %w", err)
	}

	if err := libddrcffi.EnableLogSink(writer.Fd(), level); err != nil {
		_ = writer.Close()
		_ = reader.Close()
		return err
	}

	// Ownership of the fd behind writer has now passed to the client
	// library, which keeps it open for the life of the process and is the
	// only thing writing to it going forward. Disarm writer's finalizer so
	// Go doesn't close that same fd out from under it once writer (never
	// referenced again after this function returns) becomes unreachable.
	runtime.SetFinalizer(writer, nil)

	go func() {
		defer reader.Close()
		_, _ = io.Copy(w, reader)
	}()

	return nil
}
