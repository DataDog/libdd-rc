package rcx509

import (
	"os"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi"
)

// EnableLogSink installs `f` as the destination for tracing events emitted by
// the underlying client library, for local debugging.
//
// Callers must ensure the os.File remains open and reachable to keep the
// underlying file descriptor live throughout the process's lifetime.
func EnableLogSink(f *os.File) error {
	return libddrcffi.EnableLogSink(f)
}
