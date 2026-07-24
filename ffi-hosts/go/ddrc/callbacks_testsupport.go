package ddrc

/*
#include "libdd_rc.h"
#include <stdlib.h>
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

// This file exists only to drive goDispatchCb/goSendCb directly from tests.
// Go's module indexer rejects `import "C"` in _test.go files (even internal
// test files), so the cgo-touching pieces of the test scaffolding live here
// instead, exposed to callbacks_test.go through plain Go types.

// Numeric mirrors of the C return-code constants, usable from cgo-free test
// files.
const (
	testDispatchRetSuccess           = int32(C.DISPATCH_RET_SUCCESS)
	testDispatchRetUnknownPayload    = int32(C.DISPATCH_RET_UNKNOWN_PAYLOAD)
	testDispatchRetNoDispatchHandler = int32(C.DISPATCH_RET_NO_DISPATCH_HANDLER)
	testDispatchRetQueueFull         = int32(C.DISPATCH_RET_QUEUE_FULL)
	testDispatchRetUnknown           = int32(C.DISPATCH_RET_UNKNOWN)
	testSendRetSuccess               = int32(C.SEND_RET_T_SUCCESS)
	testSendRetUnknown               = int32(C.SEND_RET_T_UNKNOWN)
)

// testUserData mirrors the user_data value NewConnection registers with the
// client library, without going through rc_conn_new.
type testUserData struct {
	handle cgo.Handle
}

func newTestUserData(st *connState) *testUserData {
	return &testUserData{handle: cgo.NewHandle(st)}
}

func (u *testUserData) free() {
	u.handle.Delete()
}

// value is the user_data pointer the callbacks receive. It stays valid after
// free() so tests can exercise the stale-handle path.
func (u *testUserData) value() unsafe.Pointer {
	return unsafe.Pointer(uintptr(u.handle))
}

func callGoDispatchCb(correlationID uint64, data []byte, u *testUserData) int32 {
	var ptr *C.uint8_t
	var userData unsafe.Pointer
	if u != nil {
		userData = u.value()
	}
	if len(data) > 0 {
		cData := C.CBytes(data)
		defer C.free(cData)
		ptr = (*C.uint8_t)(cData)
	}
	return int32(goDispatchCb(C.uint64_t(correlationID), ptr, C.uint32_t(len(data)), userData))
}

func callGoSendCb(data []byte, u *testUserData) int32 {
	var ptr *C.uint8_t
	var userData unsafe.Pointer
	if u != nil {
		userData = u.value()
	}
	if len(data) > 0 {
		cData := C.CBytes(data)
		defer C.free(cData)
		ptr = (*C.uint8_t)(cData)
	}
	return int32(goSendCb(ptr, C.uint32_t(len(data)), userData))
}
