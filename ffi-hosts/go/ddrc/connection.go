package ddrc

/*
#include "libdd_rc.h"
#include <stdlib.h>

// Forward declarations for the goDispatchCb/goSendCb functions exported from
// callbacks.go: cgo requires these to reference them from another file in
// the same package.
extern DispatchRet goDispatchCb(uint64_t correlation_id, uint8_t *data, uint32_t length, void *user_data);
extern send_ret_t goSendCb(uint8_t *data, uint32_t length, void *user_data);
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"runtime/cgo"
	"sync"
	"unsafe"

	"google.golang.org/protobuf/proto"

	magictunnelv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel"
	protocolv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/protocol"
)

// TODO: These can be refined, but we needed some kind of placeholder as
// I don't think we want this unbounded.
const (
	dispatchQueueCap = 100
	outgoingQueueCap = 100
)

// ErrConnectionClosed is returned when an operation is attempted on a
// Connection that has already been freed.
var ErrConnectionClosed = errors.New("ddrc: connection is closed")

// ErrConnectionNotConnected is returned by operations that require an
// established connection, but were called on a Connection that Connected was
// never called on.
//
// The rc-x509-client backend panics rather than reporting an error when it is
// driven out of order, which would abort the host process, so these
// transitions are checked here before crossing the FFI boundary. Disconnected
// returns this error too: it skips notifying the backend in that case, but
// still releases the connection's resources.
var ErrConnectionNotConnected = errors.New("ddrc: connection was never connected")

// ErrConnectionAlreadyConnected is returned by Connected when the Connection
// has already been marked as established.
var ErrConnectionAlreadyConnected = errors.New("ddrc: connection is already connected")

// ErrEmptyPayload is returned by Recv when passed a zero-length payload,
// which is not representable across the FFI boundary.
var ErrEmptyPayload = errors.New("ddrc: payload is empty")

// dispatchJob is a single DispatchCb invocation, already decoded and routed
// to a handler by goDispatchCb, queued for processing by the dispatch worker
// goroutine.
type dispatchJob struct {
	correlationID uint64
	handler       HandlerFunc
	request       *magictunnelv1.MagicTunnelRequest
}

// connState holds the state reachable from the exported callbacks via a
// cgo.Handle passed as user_data. It must remain valid for as long as Rust
// may invoke the callbacks, i.e. until rc_conn_free returns.
type connState struct {
	conn          *C.FFIConnection
	dispatchQueue chan dispatchJob
	outgoing      chan []byte

	// Allows for control of internal goroutines to process
	// incoming/outgoing requests
	stop chan struct{}
	wg   sync.WaitGroup

	// dispatchMu guards accepting, and is held over the enqueue onto
	// dispatchQueue, so that the queue contents become final the moment
	// Disconnected clears accepting: a goDispatchCb call blocked here wakes to
	// accepting == false and rejects the payload rather than queueing work no
	// dispatch worker is left to answer.
	dispatchMu sync.Mutex
	accepting  bool

	// handlePtr is a standalone heap allocation (not a field alongside
	// pinner or the other pointer-typed fields above) holding the cgo.Handle
	// for this connState. *handlePtr is what gets passed across the FFI
	// boundary as user_data.
	//
	// It must live in its own allocation containing nothing else: the cgo
	// pointer-passing rules forbid passing a Go pointer into memory that
	// itself contains other Go pointers, so handlePtr cannot be a field
	// sitting next to connState's channels, or even next to pinner, whose
	// own internal bookkeeping is itself a Go pointer.
	//
	// pinner keeps *handlePtr safe to hand to C: rc-x509-client retains
	// user_data and hands it back on every subsequent DispatchCb/SendCb
	// call rather than using it only for the duration of a single call,
	// which is exactly the case runtime/cgo's docs require a
	// runtime.Pinner for.
	handlePtr *cgo.Handle
	pinner    runtime.Pinner
}

// Connection represents a unique connection between the RC X509
// backend and the host's rc-x509-client instance.
type Connection struct {
	mu  sync.Mutex
	ctx *X509Context

	closed    bool
	connected bool

	// Used to broker connection specific information across the FFI
	// boundry so that Go can find the connection without a global
	// lookup table
	st *connState
}

// NewConnection creates a new Connection bound to c: it calls rc_conn_new,
// registers the send callback, and starts the dispatch worker goroutine that
// routes dispatched payloads through the package-global dispatcher.
//
// The caller is responsible for signaling later to the rc-x509-client
// system that the backend has connected via Connected().
func (c *X509Context) NewConnection() (*Connection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrContextClosed
	}

	st := &connState{
		dispatchQueue: make(chan dispatchJob, dispatchQueueCap),
		outgoing:      make(chan []byte, outgoingQueueCap),
		stop:          make(chan struct{}),
		accepting:     true,
	}

	// The handle is passed across the FFI boundary as st.handlePtr, and is
	// what lets the callbacks find this connection's state without a
	// package-global lookup table. It stays valid until rc_conn_free()
	// returns, after which the client library guarantees no further
	// callbacks.
	st.handlePtr = new(cgo.Handle)
	*st.handlePtr = cgo.NewHandle(st)
	st.pinner.Pin(st.handlePtr)
	userData := unsafe.Pointer(st.handlePtr)

	connPtr := C.rc_conn_new(c.ptr, C.DispatchCb(C.goDispatchCb), userData)
	if connPtr == nil {
		st.pinner.Unpin()
		st.handlePtr.Delete()
		return nil, errors.New("ddrc: rc_conn_new returned a nil connection")
	}
	st.conn = connPtr

	// Our send callback is generic, so we can go ahead and set this for
	// the newly established connection
	C.rc_conn_send_callback(connPtr, C.SendCb(C.goSendCb), userData)

	conn := &Connection{ctx: c, st: st}
	c.conns[conn] = struct{}{}

	st.wg.Add(1)
	go conn.dispatchWorker()

	return conn, nil
}

// Connected signals to the host's rc-x509-client instance that we have
// an established connection to the RC backend.
//
// It can only be called once per Connection, there is no concept of
// reconnection to the rx-509-client system.
func (c *Connection) Connected() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrConnectionClosed
	}
	if c.connected {
		return ErrConnectionAlreadyConnected
	}

	C.rc_conn_connected(c.st.conn)
	c.connected = true

	return nil
}

// Disconnected singals to the host's rc-x509-client instance that we have
// lost the connection to the RC backend, either lost or closed.
//
// Since there is no ability for a connection to be reconnected once
// it has disconnected, Disconnected also frees the connection
// resources.
//
// It blocks until dispatched payloads that have already been accepted have
// been handled and answered, which includes waiting for in-flight handler
// calls to return.
//
// If Connected was never called, the rc-x509-client backend is not notified
// (doing so would panic), but the connection's resources are still freed as we
// proactively fire up the worker goroutines.
// ErrConnectionNotConnected is returned in that case.
func (c *Connection) Disconnected() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrConnectionClosed
	}
	c.closed = true
	wasConnected := c.connected

	// Stop accepting dispatched payloads before signalling the worker. Once
	// this returns, the queue contents are final, so the worker's drain
	// answers every payload goDispatchCb accepted, and payloads arriving
	// during the rest of the teardown are refused at the callback rather than
	// accepted and abandoned.
	c.st.dispatchMu.Lock()
	c.st.accepting = false
	c.st.dispatchMu.Unlock()

	// Stop the connection processing pipeline. The drain runs before
	// rc_conn_disconnected below, because rc-x509-client discards dispatch
	// results for a connection that is no longer connected.
	close(c.st.stop)
	c.st.wg.Wait()

	if wasConnected {
		C.rc_conn_disconnected(c.st.conn)
	}

	C.rc_conn_free(c.st.conn)
	c.st.pinner.Unpin()
	c.st.handlePtr.Delete()

	c.mu.Unlock()

	// Released, so the context is free to shut down. Done outside the
	// connection lock: nothing else takes the context lock while holding it.
	c.ctx.forget(c)

	if !wasConnected {
		return ErrConnectionNotConnected
	}

	return nil
}

// Recv passes data received from the RC delivery backend into the host's rc-x509-client
// instance.
//
// Connected must have been called first, and data must not be empty:
// rc_conn_recv asserts the payload pointer is non-null, and panics if the
// connection is not established, either of which aborts the process.
//
// Recv can block while a concurrent Disconnected tears the connection down,
// which includes waiting for in-flight dispatch handlers to return.
func (c *Connection) Recv(data []byte) error {
	if len(data) == 0 {
		return ErrEmptyPayload
	}

	// The lock is held across the call into the client library: releasing it
	// beforehand would let a concurrent Disconnected free the FFIConnection
	// that rc_conn_recv is about to be handed.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Safety check to make sure we weren't waiting on the lock because
	// the connection was closing down.
	if c.closed {
		return ErrConnectionClosed
	}
	if !c.connected {
		return ErrConnectionNotConnected
	}

	if ret := C.rc_conn_recv(c.st.conn, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.uint32_t(len(data))); ret != C.RECV_RET_T_SUCCESS {
		return fmt.Errorf("ddrc: rc_conn_recv returned %v", ret)
	}

	return nil
}

// dispatchWorker drains dispatchQueue, routing each job through the
// package-global dispatcher and reporting the result back via
// rc_conn_dispatch_result, until stop is closed.
func (c *Connection) dispatchWorker() {
	defer c.st.wg.Done()
	for {
		select {
		case job := <-c.st.dispatchQueue:
			c.handleDispatchJob(job)
		case <-c.st.stop:
			c.drainDispatchQueue()
			return
		}
	}
}

// drainDispatchQueue answers the jobs left in dispatchQueue before the worker
// exits.
//
// libdd_rc.h requires exactly one rc_conn_dispatch_result call per payload
// delivered through DispatchCb, so a queued job cannot simply be discarded
// once stop is closed - not least because a select with both a ready job and
// a closed stop channel picks between them at random.
//
// Disconnected clears accepting before closing stop, so no further job can be
// enqueued and this terminates.
func (c *Connection) drainDispatchQueue() {
	for {
		select {
		case job := <-c.st.dispatchQueue:
			c.handleDispatchJob(job)
		default:
			return
		}
	}
}

// handleDispatchJob invokes job.handler with the request payload decoded and
// routed by goDispatchCb, and reports the result back via
// rc_conn_dispatch_result.
//
// DispatchRequestPayload.connection_id is intentionally not inspected here
// (nor by goDispatchCb): validating it against the server-assigned
// connection is rc-x509-client's responsibility once that part of the
// protocol is implemented, not the Go host's.
//
// A registered handler's own error IS representable on the wire
// (MagicTunnelResponse.handler_error), so it is reported back to the caller
// rather than skipped. The same is true of a handler that panics, and of a
// response that cannot be marshalled: every payload has to be answered
// exactly once, so a local failure is reported as a handler error rather than
// dropped.
func (c *Connection) handleDispatchJob(job dispatchJob) {
	response, err := invokeHandler(job)

	encoded, err := marshalDispatchResponse(response, err)
	if err != nil {
		// Reporting the marshalling failure needs marshalling too. Nothing
		// further can be said across the boundary if that fails as well.
		encoded, err = marshalDispatchResponse(nil, err)
		if err != nil {
			return
		}
	}

	// rc_conn_dispatch_result asserts its payload pointer is non-null, so a
	// zero-length response must not be forwarded. A marshalled
	// DispatchResponsePayload always carries at least the oneof field tag, so
	// this path can never be taken.
	if len(encoded) == 0 {
        encoded, _ = marshalDispatchResponse(nil, errors.New("handleDispatchJob: invalid empty serialised response"))
	}

	cData := C.CBytes(encoded)
	defer C.free(cData)

	C.rc_conn_dispatch_result(c.st.conn, C.uint64_t(job.correlationID), (*C.uint8_t)(cData), C.uint32_t(len(encoded)))
}

// invokeHandler calls the handler registered for the job's namespace,
// converting a panic in that caller-supplied code into an error.
//
// A panic must not escape: it would take down the dispatch worker, leaving
// this payload and every payload queued behind it for this connection without
// the rc_conn_dispatch_result call the client library is waiting for.
func invokeHandler(job dispatchJob) (response []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			response = nil
			err = fmt.Errorf("ddrc: dispatch handler panicked: %v", r)
		}
	}()

	return job.handler(job.correlationID, job.request.GetPayload())
}

// marshalDispatchResponse encodes the outcome of a dispatch handler as the
// DispatchResponsePayload wire format rc_conn_dispatch_result expects. A
// non-nil handlerErr is reported in place of the response.
func marshalDispatchResponse(response []byte, handlerErr error) ([]byte, error) {
	mtResp := &magictunnelv1.MagicTunnelResponse{}
	if handlerErr != nil {
		mtResp.Result = &magictunnelv1.MagicTunnelResponse_HandlerError{HandlerError: handlerErr.Error()}
	} else {
		mtResp.Result = &magictunnelv1.MagicTunnelResponse_Response{Response: response}
	}

	return proto.Marshal(&protocolv1.DispatchResponsePayload{
		Payload: &protocolv1.DispatchResponsePayload_MagicTunnel{MagicTunnel: mtResp},
	})
}
