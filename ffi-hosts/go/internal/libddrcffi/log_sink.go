package libddrcffi

/*
#include "libdd_rc.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
)

// ErrLogSinkAlreadySet is returned by EnableLogSink when a log sink has
// already been installed for this process. Only the first call takes
// effect: the client library only supports one global tracing subscriber
// per process.
//
// This isn't a hard technical restriction and can be changed if so desired.
var ErrLogSinkAlreadySet = errors.New("ddrc: log sink already installed for this process")

// EnableLogSink installs `f` as the destination for tracing events emitted by
// the client library.
//
// The file descriptor backing `f` is duplicated before being installed into the
// underlying client library; the caller continues to own `f`, and the client
// library owns and manages the lifetime of a separate descriptor. If the caller
// writes to `f` after this call, the write may be interleaved with log output.
//
// This log sink is assigned for the entire process, independent of any one
// specific RCX509Context instance.
func EnableLogSink(f *os.File) error {
	// Duplicate the descriptor, to decouple Go ownership of the underlying
	// file from the fd passed into the client library. dupLogSinkFile is
	// OS-specific (log_sink_unix.go, log_sink_windows.go).
	ffiFd, closeFfiFd, err := dupLogSinkFile(f)
	if err != nil {
		return err
	}

	// Pass the newly duplicated fd to the client library, which only takes
	// ownership of it on success.
	ret := C.rc_enable_log_sink(ffiFd)
	if ret != C.LOG_SINK_RET_T_SUCCESS {
		closeFfiFd()
	}
	switch ret {
	case C.LOG_SINK_RET_T_SUCCESS:
		return nil
	case C.LOG_SINK_RET_T_ALREADY_SET:
		return ErrLogSinkAlreadySet
	default:
		return fmt.Errorf("ddrc: rc_enable_log_sink returned %v", ret)
	}
}
