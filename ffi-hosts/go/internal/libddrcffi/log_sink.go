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
var ErrLogSinkAlreadySet = errors.New("ddrc: log sink already installed for this process")

// EnableLogSink installs fd as the destination for tracing events emitted by
// the client library, at the given level, via rc_enable_log_sink.
//
// fd's ownership passes to the client library on success: the caller must
// not use or close it afterward. On any other return, including
// ErrLogSinkAlreadySet, fd is left untouched by the client library and
// remains owned by the caller.
//
// This installs a process-global subscriber, not one scoped to a particular
// X509Context: rc_enable_log_sink takes no Ctx argument, and calling it more
// than once across any number of contexts still only ever takes effect
// once.
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
