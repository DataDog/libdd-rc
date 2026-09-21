package libddrcffi

import (
	"errors"
	"sync"

	magictunnelv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel"
	protocolv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/protocol"
	"google.golang.org/protobuf/proto"
)

// TODO: This can be refined, but we needed some kind of placeholder as I
// don't think we want this unbounded.
const outgoingQueueCap = 100

// ErrConnectionClosed is returned when an operation is attempted on a
// Connection that has already been freed.
var ErrConnectionClosed = errors.New("ddrc: connection is closed")

// ErrConnectionNotConnected is returned by operations that require an
// established connection, but were called on a Connection that Connected was
// never called on.
//
// The rc-x509-client backend panics rather than reporting an error when it is
// driven out of order, which would abort the host process, so these
// transitions are checked here before crossing the FFI boundary.
var ErrConnectionNotConnected = errors.New("ddrc: connection was never connected")

// ErrConnectionAlreadyConnected is returned by Connected when the Connection
// has already been marked as established.
var ErrConnectionAlreadyConnected = errors.New("ddrc: connection is already connected")

// ErrEmptyPayload is returned by Recv when passed a zero-length payload,
// which is not representable across the FFI boundary.
var ErrEmptyPayload = errors.New("ddrc: payload is empty")

// connState holds the state reachable from the exported callbacks via a
// cgo.Handle passed as user_data. It must remain valid for as long as Rust
// may invoke the callbacks, i.e. until rc_conn_free returns.
type connState struct {
	conn     nativeConn
	pool     *invokePool
	outgoing chan []byte

	// handle is what gets passed across the FFI boundary as user_data,
	// letting the exported callbacks find this connState without a
	// package-global lookup table. It must remain valid for as long as Rust
	// may invoke the callbacks, i.e. until rc_conn_free returns.
	handle *pinnedHandle
}

// Connection represents a unique connection between the RC X509
// backend and the host's rc-x509-client instance.
type Connection struct {
	mu        sync.Mutex
	ctx       *X509Context
	lifecycle connLifecycle

	// Used to broker connection specific information across the FFI
	// boundry so that Go can find the connection without a global
	// lookup table
	state *connState
}

// NewConnection creates a new Connection bound to c: it calls rc_conn_new,
// registers the send callback, and starts the invoke pool that routes
// dispatched payloads through the package-global handler registry and delivers
// their results back across the FFI boundary.
//
// The caller is responsible for signaling later to the rc-x509-client
// system that the backend has connected via Connected().
func (c *X509Context) NewConnection() (*Connection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrContextClosed
	}

	state := &connState{
		outgoing: make(chan []byte, outgoingQueueCap),
	}

	// The handle is passed across the FFI boundary as state.handle, and is
	// what lets the callbacks find this connection's state without a
	// package-global lookup table. It stays valid until rc_conn_free()
	// returns, after which the client library guarantees no further
	// callbacks.
	state.handle = newPinnedHandle(state)

	nc, err := newCgoConn(c.ptr, state.handle.userData())
	if err != nil {
		state.handle.release()
		return nil, err
	}
	state.conn = nc

	conn := &Connection{ctx: c, state: state}
	state.pool = newInvokePool(conn)
	c.conns[conn] = struct{}{}

	state.pool.start()

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

	if err := c.lifecycle.markConnected(); err != nil {
		return err
	}
	c.state.conn.connected()

	return nil
}

// Close shuts down a connection, freeing all supporting resources.
//
// If Connected() was never called, the rc-x509-client backend is
// not notified of a disconnect (doing so is protocol error).
//
// It blocks until dispatched payloads that have already been accepted have
// been handled and answered, which includes waiting for in-flight handler
// calls to return. Answering those payloads enqueues onto the channel returned
// by Outgoing, so a caller that wants those responses delivered to the RC
// backend has to keep draining it concurrently with this call. The channel is
// closed before Close returns.
func (c *Connection) Close() error {
	c.mu.Lock()
	wasConnected, err := c.lifecycle.markClosed()
	if err != nil {
		c.mu.Unlock()
		return err
	}

	// Stop the connection processing pipeline. The drain runs before
	// rc_conn_disconnected below, because rc-x509-client discards dispatch
	// results for a connection that is no longer connected.
	//
	// This also ensures that we don't have a use after free of the FFI connection
	// for any jobs finishing up, as shutdown allows that to close out first.
	c.state.pool.shutdown()

	if wasConnected {
		c.state.conn.disconnected()
	}

	c.state.conn.free()
	c.state.handle.release()

	// rc_conn_free has returned, so the client library guarantees no further
	// callbacks. That makes this the first point at which closing outgoing
	// cannot race a goSendCb send onto it, which would panic.
	close(c.state.outgoing)

	c.mu.Unlock()

	// Released, so the context is free to shut down. Done outside the
	// connection lock: nothing else takes the context lock while holding it.
	c.ctx.forget(c)

	return nil
}

// Recv passes data received from the RC delivery backend into the host's rc-x509-client
// instance.
//
// Connected must have been called first, and data must not be empty:
// rc_conn_recv asserts the payload pointer is non-null, and panics if the
// connection is not established, either of which aborts the process.
//
// Recv can block while a concurrent Close tears the connection down,
// which includes waiting for in-flight dispatch handlers to return.
func (c *Connection) Recv(data []byte) error {
	if len(data) == 0 {
		return ErrEmptyPayload
	}

	// The lock is held across the call into the client library: releasing it
	// beforehand would let a concurrent Close free the FFIConnection
	// that rc_conn_recv is about to be handed.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Safety check to make sure we weren't waiting on the lock because
	// the connection was closing down.
	if err := c.lifecycle.checkRecvable(); err != nil {
		return err
	}

	return c.state.conn.recv(data)
}

// Outgoing returns the channel carrying payloads that rc-x509-client wants
// written to the RC backend.
//
// The caller is expected to keep draining it for the lifetime of the
// connection, including while Close is running: the dispatch results
// produced by the shutdown drain are enqueued here, and goSendCb drops
// payloads rather than blocking once the channel is full.
//
// Close closes the channel once the connection has been freed, so a
// receive reporting the channel as closed means every payload the client
// library will ever produce has already been delivered.
func (c *Connection) Outgoing() <-chan []byte {
	return c.state.outgoing
}

// sendDispatchResult implements resultSink for invokePool: it marshals
// result and reports it back via rc_conn_dispatch_result.
//
// A registered handler's own error IS representable on the wire
// (MagicTunnelResponse.handler_error), so it is reported back to the caller
// rather than skipped. The same is true of a handler that panicked, and of a
// response that cannot be marshalled: every payload has to be answered
// exactly once, so a local failure is reported as a handler error rather than
// dropped.
func (c *Connection) sendDispatchResult(result dispatchResult) {
	encoded, err := marshalDispatchResponse(result.response, result.err)
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
		encoded, _ = marshalDispatchResponse(nil, errors.New("sendDispatchResult: invalid empty serialised response"))
	}

	c.state.conn.dispatchResult(result.correlationID, encoded)
}

func (c *Connection) sendDispatchError(correlationID uint64, errorCode int) {
	c.state.conn.dispatchError(correlationID, errorCode)
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
