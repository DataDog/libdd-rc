package libddrcffi

/*
#include "libdd_rc.h"
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"

	"google.golang.org/protobuf/proto"

	protocolv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/protocol"
)

// goDispatchCb is the DispatchCb registered with rc_conn_new. It MUST NOT
// block: it copies the payload immediately (data ownership is only shared for the
// duration of this call), decodes it, resolves the handler for it, and
// enqueues the result for the connections' worker goroutine.
//
// Safety:
//
// The libdd_rc.h contract mandates this must not:
//   - Block (this is called synchronously by rc-x509-client)
//   - Assume the data pointer lives longer than this function's lifetime
//   - Panic (see recoverCallback)
//
//export goDispatchCb
func goDispatchCb(correlationID C.uint64_t, data *C.uint8_t, length C.uint32_t, userData unsafe.Pointer) (ret C.DispatchRet) {
	defer recoverCallback(func() { ret = C.DISPATCH_RET_UNKNOWN })

	// It doesn't really matter what the payload is if we can't find the connection specific
	// information we need to route the request for processing
	st, ok := connStateFromUserData(userData)
	if !ok {
		return C.DISPATCH_RET_UNKNOWN
	}

	var req protocolv1.DispatchRequestPayload
	if err := proto.Unmarshal(C.GoBytes(unsafe.Pointer(data), C.int(length)), &req); err != nil {
		return C.DISPATCH_RET_UNKNOWN_PAYLOAD
	}

	// Right now, the only valid type for the embedded message is the MagicTunnel payload.
	// This will have to change when we have other known valid types.
	mt := req.GetMagicTunnel()
	if mt == nil {
		return C.DISPATCH_RET_UNKNOWN_PAYLOAD
	}

	// It's possible that nothing on this client has registered to handle this
	// namespace - if so we need to signal this explicitly the FFI library
	handler, ok := globalDispatcher.lookup(mt.GetNamespace())
	if !ok {
		return C.DISPATCH_RET_NO_DISPATCH_HANDLER
	}

	job := dispatchJob{
		correlationID: uint64(correlationID),
		handler:       handler,
		request:       mt,
	}

    // Aquire the lock to check the validity of this connState and enqueue
    // the job if valid.
    // 
    // This lock only contends with the connection close path.
	st.dispatchMu.Lock()
	defer st.dispatchMu.Unlock()
	// The connection is being torn down, and the dispatch worker that would
	// answer this payload is already stopping. DispatchRet has no "closed"
	// variant, and QUEUE_FULL carries the part that matters to the client
	// library: the message will not be delivered.
	if !st.accepting {
		return C.DISPATCH_RET_QUEUE_FULL
	}

	select {
	case st.dispatchQueue <- job:
		return C.DISPATCH_RET_SUCCESS
	default:
		return C.DISPATCH_RET_QUEUE_FULL
	}
}

// goSendCb is the SendCb registered with rc_conn_send_callback. It MUST NOT
// block or panic: it copies the payload immediately and enqueues it onto the
// connection's outgoing channel, returning SEND_RET_T_UNKNOWN rather than
// blocking if the queue is full.
//
//export goSendCb
func goSendCb(data *C.uint8_t, length C.uint32_t, userData unsafe.Pointer) (ret C.send_ret_t) {
	defer recoverCallback(func() { ret = C.SEND_RET_T_UNKNOWN })

	st, ok := connStateFromUserData(userData)
	if !ok {
		return C.SEND_RET_T_UNKNOWN
	}

	payload := C.GoBytes(unsafe.Pointer(data), C.int(length))

	select {
	case st.outgoing <- payload:
		return C.SEND_RET_T_SUCCESS
	default:
		return C.SEND_RET_T_UNKNOWN
	}
}

// recoverCallback stops a panic from escaping an exported callback, invoking
// onPanic to substitute an error return code.
//
// rc-x509-client invokes the callbacks through an extern "C" function
// declared as non-unwinding, so a panic crossing back out of Go does not
// unwind: it aborts the process. Every failure inside a callback has to be
// expressible as a return code instead.
//
// The client library's contract makes the reachable case here -
// cgo.Handle.Value() panicking on a handle already released by
// Disconnected() - impossible, since no callback is invoked after
// rc_conn_free() returns. This is the boundary where being wrong about that
// costs the host process, so the guard stays.
func recoverCallback(onPanic func()) {
	if r := recover(); r != nil {
		onPanic()
	}
}

// connStateFromUserData resolves the connState behind the user_data value
// registered with rc_conn_new / rc_conn_send_callback, which carries the
// address of the connection's cgo.Handle.
func connStateFromUserData(userData unsafe.Pointer) (*connState, bool) {
	if userData == nil {
		return nil, false
	}
	handle := *(*cgo.Handle)(userData)
	st, ok := handle.Value().(*connState)
	return st, ok
}
