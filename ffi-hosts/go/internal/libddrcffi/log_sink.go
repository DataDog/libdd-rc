package libddrcffi

/*
#include "libdd_rc.h"
*/
import "C"

import (
	"errors"
	"fmt"
)

// LogLevel selects the verbosity of events written by a log sink installed
// via EnableLogSink.
type LogLevel int32

const (
	LogLevelOff LogLevel = iota
	LogLevelError
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

// ErrLogSinkAlreadySet is returned by EnableLogSink when a log sink has
// already been installed for this process. Only the first call takes
// effect: the client library only supports one global tracing subscriber
// per process.
//
// This isn't a hard technical restriction and can be changed if so desired.
var ErrLogSinkAlreadySet = errors.New("ddrc: log sink already installed for this process")

// EnableLogSink installs fd as the destination for tracing events emitted by
// the client library, at the given level.
//
// Since this assignment lasts for the duration of the process's lifetime,
// ownership is technically transferred to the FFI library, and the Go
// client must make sure to keep the underlying file descriptor open,
// whatever that entails for how it was created.
//
// This log sink is assigned for the entire process, independent of any one
// specific RCX509Context instance.
func EnableLogSink(fd uintptr, level LogLevel) error {
	ret := C.rc_enable_log_sink(C.int(fd), C.int(level))
	switch ret {
	case C.LOG_SINK_RET_T_SUCCESS:
		return nil
	case C.LOG_SINK_RET_T_ALREADY_SET:
		return ErrLogSinkAlreadySet
	default:
		return fmt.Errorf("ddrc: rc_enable_log_sink returned %v", ret)
	}
}
