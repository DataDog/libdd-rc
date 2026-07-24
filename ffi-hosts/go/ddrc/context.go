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

// ErrConnectionsOpen is returned by Close when connections created from the
// context have not been released yet.
var ErrConnectionsOpen = errors.New("libddrc: context still has open connections")

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
	// freed beforehand, so Close refuses to run while any remain.
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

// Close triggers shutdown of the rc-x509-client subsystem
//
// Every Connection created from this context must have been released with
// Connection.Disconnected first, else Close returns ErrConnectionsOpen: the
// connections are owned by their callers, and rc-x509-client aborts the
// process if one outlives the context it belongs to.
//
// It is an error to call Close more than once.
func (c *X509Context) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrContextClosed
	}
	if len(c.conns) > 0 {
		return fmt.Errorf("%w: %d remaining", ErrConnectionsOpen, len(c.conns))
	}

	C.rc_free(c.ptr)
	c.ptr = nil
	c.closed = true
	return nil
}

// forget drops the context's record of a connection that has been released.
func (c *X509Context) forget(conn *Connection) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.conns, conn)
}
