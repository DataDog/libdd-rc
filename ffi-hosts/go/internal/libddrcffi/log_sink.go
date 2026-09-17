package libddrcffi

/*
#include "libdd_rc.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"syscall"
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
// The file descriptor backing `f` is dup'd here so that we can close Go's
// copy and pass ownership of the underlying descriptor to the Rust library.
//
// This log sink is assigned for the entire process, independent of any one
// specific RCX509Context instance.
func EnableLogSink(f *os.File) error {
	// Duplicate the descriptor, to decouple Go ownership of the underlying
	// file from the fd passed into the client library.
	ffiFd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		return err
	}
	_ = f.Close() // Release Go ownership

	// Pass the newly duplicated fd to the client library.
	ret := C.rc_enable_log_sink(C.int(ffiFd))
	switch ret {
	case C.LOG_SINK_RET_T_SUCCESS:
		return nil
	case C.LOG_SINK_RET_T_ALREADY_SET:
		return ErrLogSinkAlreadySet
	default:
		return fmt.Errorf("ddrc: rc_enable_log_sink returned %v", ret)
	}
}
