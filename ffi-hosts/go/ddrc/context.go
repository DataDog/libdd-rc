package ddrc

/*
#include "libdd_rc.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"
)

// ErrContextClosed is returned when an operation is attempted on an
// FFIContext that has already been closed.
var ErrContextClosed = errors.New("ddrc: context is closed")

// X509Context encapsulates a connection to a concrete instance of the
// rc-x509-client subsystem.
//
// The rc-x509-client subsystem is self-contained, with its own processing
// engine that we interact with here in Go through a C FFI.
type X509Context struct {
	mu     sync.Mutex
	ptr    *C.Ctx
	closed bool

	// conns are the connections created from this context that have not been
	// released yet. rc_free requires every connection be disconnected and
	// freed beforehand, so Close force-disconnects any that remain.
	conns map[*Connection]struct{}
}

// Init initializes an instance of the rc-x509-client subsystem
func Init() (*X509Context, error) {
	ptr := C.rc_init()
	if ptr == nil {
		return nil, errors.New("libddrc: rc_init returned a nil context")
	}
	return &X509Context{ptr: ptr, conns: make(map[*Connection]struct{})}, nil
}

// Close triggers shutdown of the rc-x509-client subsystem.
//
// Any Connection created from this context that has not already been
// released is force-disconnected first: rc_free requires every connection be
// disconnected and freed beforehand, and rc-x509-client aborts the process if
// one outlives the context it belongs to, so Close cannot leave that to the
// caller to remember.
//
// It is an error to call Close more than once.
func (c *X509Context) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrContextClosed
	}
	// Marked closed before releasing the lock so that no new connection can
	// be created while the ones snapshotted below are being torn down.
	c.closed = true
	conns := make([]*Connection, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	c.mu.Unlock()

	for _, conn := range conns {
		// ErrConnectionNotConnected/ErrConnectionClosed are expected here: the
		// former just means Connected was never called, and the latter means
		// something else (e.g. the caller) already disconnected it
		// concurrently. Either way the connection's resources end up freed.
		if err := conn.Disconnected(); err != nil &&
			!errors.Is(err, ErrConnectionNotConnected) &&
			!errors.Is(err, ErrConnectionClosed) {
			return fmt.Errorf("ddrc: failed to disconnect connection during Close: %w", err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	C.rc_free(c.ptr)
	c.ptr = nil
	return nil
}

// forget drops the context's record of a connection that has been released.
func (c *X509Context) forget(conn *Connection) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.conns, conn)
}
