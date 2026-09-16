package libddrcffi

import (
	"runtime"
	"runtime/cgo"
	"unsafe"
)

// pinnedHandle is a cgo.Handle pinned for as long as C code may hold onto
// its address, and is safe to pass across the FFI boundary as a stable
// user_data pointer.
//
// The handle lives in its own standalone allocation, never as a field
// embedded alongside other data: the cgo pointer-passing rules forbid
// passing a Go pointer into memory that itself contains other Go pointers,
// and a runtime.Pinner's own internal bookkeeping counts as one.
//
// Pinning is required because rc-x509-client retains user_data and hands it
// back on every subsequent callback invocation rather than using it only for
// the duration of a single call, which is exactly the case runtime/cgo's
// docs require a runtime.Pinner for.
type pinnedHandle struct {
	ptr    *cgo.Handle
	pinner runtime.Pinner
}

// newPinnedHandle creates a cgo.Handle for value and pins it. release must
// be called once the handle is no longer needed.
func newPinnedHandle(value any) *pinnedHandle {
	h := &pinnedHandle{ptr: new(cgo.Handle)}
	*h.ptr = cgo.NewHandle(value)
	h.pinner.Pin(h.ptr)
	return h
}

// userData is the value to pass across the FFI boundary as user_data.
func (h *pinnedHandle) userData() unsafe.Pointer {
	return unsafe.Pointer(h.ptr)
}

// release unpins and deletes the handle. No further FFI calls may reference
// a value returned by userData afterwards.
func (h *pinnedHandle) release() {
	h.pinner.Unpin()
	h.ptr.Delete()
}
