//go:build !windows

package libddrcffi

/*
#include "libdd_rc.h"
*/
import "C"

import (
	"os"
	"syscall"
)

// dupLogSinkFile duplicates the fd backing f, returning it and a function that
// closes it.
func dupLogSinkFile(f *os.File) (C.int, func(), error) {
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		return 0, nil, err
	}
	return C.int(fd), func() { _ = syscall.Close(fd) }, nil
}
