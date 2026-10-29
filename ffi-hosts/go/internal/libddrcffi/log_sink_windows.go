//go:build windows

package libddrcffi

/*
#include "libdd_rc.h"
*/
import "C"

import (
	"os"
	"syscall"
)

// dupLogSinkFile duplicates the HANDLE backing f, returning it and a function
// that closes it.
//
// Passing the HANDLE as a C int is lossless: Windows handles have only 32
// significant bits. See
// https://learn.microsoft.com/en-us/windows/win32/winprog64/interprocess-communication
func dupLogSinkFile(f *os.File) (C.int, func(), error) {
	// A nil or closed f returns InvalidHandle, which DuplicateHandle would
	// accept as the current process's pseudo-handle.
	src := syscall.Handle(f.Fd())
	if src == syscall.InvalidHandle {
		return 0, nil, syscall.ERROR_INVALID_HANDLE
	}
	proc, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, nil, err
	}
	var h syscall.Handle
	err = syscall.DuplicateHandle(proc, src, proc, &h, 0, false, syscall.DUPLICATE_SAME_ACCESS)
	if err != nil {
		return 0, nil, err
	}
	return C.int(int32(h)), func() { _ = syscall.CloseHandle(h) }, nil
}
