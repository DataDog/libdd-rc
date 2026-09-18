package rcx509

import (
	"os"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi"
)

// EnableLogSink installs `f` as the destination for tracing events emitted by
// the underlying client library, for local debugging.
//
// A handle to the log destination `f` is duplicated and retained by the logging
// subsystem. The caller is responsible for the lifecycle of `f` only.
//
// NOTE: writing to `f` after this call will result in the write being
// interleaved with log output, and should be avoided.
func EnableLogSink(f *os.File) error {
	return libddrcffi.EnableLogSink(f)
}
