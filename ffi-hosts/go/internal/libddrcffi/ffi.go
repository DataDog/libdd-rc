package libddrcffi

// NOTE: rc-crypto defaults to the "fips" feature, and AWS-LC's FIPS-validated
// crypto module ships only as a shared object (never a static archive) since
// it must verify its own binary at load time. librc_x509_ffi.a is linked
// statically, but the FIPS crypto module must still be linked dynamically;
// `make libffi` copies the version-named lib (e.g.
// libaws_lc_fips_0_13_16_crypto) to the version-agnostic
// libaws_lc_fips_crypto next to librc_x509_ffi.a in target/release, so the
// -laws_lc_fips_crypto link below stays valid across aws-lc-fips-sys version
// bumps in Cargo.lock.

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../include
#cgo darwin LDFLAGS: -L${SRCDIR}/../../../../target/release -lrc_x509_ffi -laws_lc_fips_crypto -liconv -framework CoreFoundation -framework Security -lm -Wl,-rpath,${SRCDIR}/../../../../target/release
#cgo linux LDFLAGS: -L${SRCDIR}/../../../../target/release -lrc_x509_ffi -laws_lc_fips_crypto -lpthread -ldl -lm -Wl,-rpath,${SRCDIR}/../../../../target/release
#include "libdd_rc.h"

extern DispatchRet goDispatchCb(uint64_t correlation_id, uint8_t *data, uint32_t length, void *user_data);
extern send_ret_t goSendCb(uint8_t *data, uint32_t length, void *user_data);
*/
import "C"
import (
	"errors"
	"fmt"
	"log"
	"runtime/cgo"
	"unsafe"

	protocolv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/protocol"
	"google.golang.org/protobuf/proto"
)

const (
	DispatchErrorTimeout = C.DISPATCH_HOST_ERROR_HANDLER_EXEC_TIMEOUT
)

// nativeConn is the seam between Connection and the raw rc_conn_* calls
// crossing the FFI boundary. The concrete implementation, cgoConn, wraps a
// *C.FFIConnection; tests substitute a fake nativeConn to exercise
// Connection's state machine and worker plumbing without linking the native
// library.
type nativeConn interface {
	// connected reports the connection as established to rc-x509-client.
	connected()

	// recv passes data received from the RC delivery backend into
	// rc-x509-client. data must be non-empty.
	recv(data []byte) error

	// disconnected reports the connection as torn down to rc-x509-client.
	disconnected()

	// dispatchResult reports the outcome of a dispatched job back across the
	// FFI boundary. encoded must be non-empty.
	dispatchResult(correlationID uint64, encoded []byte)

	// dispatchError reports the outcome of a dispatched job that failed to
	// complete across the FFI boundary.
	dispatchError(correlationID uint64, errorCode int)

	// free releases the underlying FFIConnection. No further calls may be
	// made on this nativeConn afterwards.
	free()
}

// cgoConn is the real nativeConn, backed by a *C.FFIConnection.
type cgoConn struct {
	ptr *C.FFIConnection
}

// newCgoConn calls rc_conn_new and registers the send callback for the
// resulting connection. userData is the value both callbacks receive as
// user_data, letting them resolve the connState that owns this connection.
func newCgoConn(ctxPtr *C.Ctx, userData unsafe.Pointer) (*cgoConn, error) {
	ptr := C.rc_conn_new(ctxPtr, C.DispatchCb(C.goDispatchCb), userData)
	if ptr == nil {
		return nil, errors.New("ddrc: rc_conn_new returned a nil connection")
	}

	// Our send callback is generic, so we can go ahead and set this for the
	// newly established connection.
	if ret := C.rc_conn_send_callback(ptr, C.SendCb(C.goSendCb), userData); ret != C.CONN_RET_T_SUCCESS {
		log.Printf("ddrc: rc_conn_send_callback returned %v", ret)
	}

	return &cgoConn{ptr: ptr}, nil
}

func (c *cgoConn) connected() {
	if ret := C.rc_conn_connected(c.ptr); ret != C.CONN_RET_T_SUCCESS {
		log.Printf("ddrc: rc_conn_connected returned %v", ret)
	}
}

func (c *cgoConn) recv(data []byte) error {
	if ret := C.rc_conn_recv(c.ptr, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.uint32_t(len(data))); ret != C.RECV_RET_T_SUCCESS {
		return fmt.Errorf("ddrc: rc_conn_recv returned %v", ret)
	}
	return nil
}

func (c *cgoConn) disconnected() {
	if ret := C.rc_conn_disconnected(c.ptr); ret != C.CONN_RET_T_SUCCESS {
		log.Printf("ddrc: rc_conn_disconnected returned %v", ret)
	}
}

func (c *cgoConn) dispatchResult(correlationID uint64, encoded []byte) {
	// rc_conn_dispatch_result only requires data to be valid for the
	// duration of the call (like rc_conn_recv), so encoded can be passed
	// directly rather than copied into C memory first: the client library
	// makes its own copy before returning.
	C.rc_conn_dispatch_result(c.ptr, C.uint64_t(correlationID), (*C.uint8_t)(unsafe.Pointer(&encoded[0])), C.uint32_t(len(encoded)))
}

func (c *cgoConn) dispatchError(correlationID uint64, errorCode int) {
	C.rc_conn_dispatch_error(c.ptr, C.uint64_t(correlationID), C.int(errorCode))
}

func (c *cgoConn) free() {
	if ret := C.rc_conn_free(c.ptr); ret != C.CONN_RET_T_SUCCESS {
		log.Printf("ddrc: rc_conn_free returned %v", ret)
	}
}

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
	// uri - if so we need to signal this explicitly the FFI library
	handler, ok := globalHandlerRegistry.lookup(mt.GetUri())
	if !ok {
		return C.DISPATCH_RET_NO_DISPATCH_HANDLER
	}

	job := dispatchJob{
		correlationID: uint64(correlationID),
		handler:       handler,
		request:       mt,
	}

	// DispatchRet has no "closed" variant, and QUEUE_FULL carries the part
	// that matters to the client library either way: the message will not be
	// delivered, whether because the pool is full or because the connection
	// is being torn down and the workers that would answer it are already
	// stopping.
	if !st.pool.enqueue(job) {
		return C.DISPATCH_RET_QUEUE_FULL
	}
	return C.DISPATCH_RET_SUCCESS
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
// Close() - impossible, since no callback is invoked after
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
