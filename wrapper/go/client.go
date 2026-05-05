// Copyright 2026-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package libddrc

/*
#cgo CFLAGS: -I../../include
#cgo LDFLAGS: -L../../target/release -lrc_x509_ffi -Wl,-rpath,${SRCDIR}/../../target/release
#include <stdlib.h>
#include "libdd_rc.h"
#include "callback.h"
*/
import "C"
import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime/cgo"
	"sync"
	"unsafe"
)

// RecvRet represents the result of pushing data received from the RC delivery
// backend into the internal client library recv queue.
type RecvRet int32

const (
	// RecvRetSuccess indicates the message was successfully passed.
	RecvRetSuccess RecvRet = C.RECV_RET_T_SUCCESS
)

// SendRet represents the result of sending data to the RC delivery backend,
// returned by the host runtime.
type SendRet int32

const (
	// SendRetSuccess indicates the FFI host accepted this request.
	SendRetSuccess SendRet = C.SEND_RET_T_SUCCESS
	// SendRetClosed indicates the connection is closed on the FFI side.
	SendRetClosed SendRet = C.SEND_RET_T_CLOSED
	// SendRetUnknown indicates an unknown error occurred.
	SendRetUnknown SendRet = C.SEND_RET_T_UNKNOWN
)

// SendCallback is a function that sends data from the client library to the
// RC delivery backend over the network connection.
//
// The callback receives a byte slice containing the data to send.
// It should return SendRetSuccess if the data was accepted,
// SendRetClosed if the connection is closed, or SendRetUnknown for other errors.
type SendCallback func(data []byte) SendRet

//export goSendCallback
func goSendCallback(data *C.uint8_t, length C.uint32_t, userData unsafe.Pointer) C.send_ret_t {
	handle := cgo.Handle(uintptr(userData))
	cc, ok := handle.Value().(*ClientConnection)
	if !ok {
		return C.send_ret_t(SendRetUnknown)
	}

	goData := C.GoBytes(unsafe.Pointer(data), C.int(length))
	toGo := make([]byte, len(goData))
	copy(toGo, goData)
	ret := cc.sendCallback(toGo)
	return C.send_ret_t(ret)
}

var (
	// ErrClientClosed is returned when operations are attempted on a closed client.
	ErrClientClosed = errors.New("client is closed")
	// ErrConnectionClosed is returned when operations are attempted on a closed connection.
	ErrConnectionClosed = errors.New("connection is closed")
	// ErrNoSender is returned when a connection is used without configuring a sender.
	ErrNoSender = errors.New("sender not configured")
	// ErrNotConnected is returned when operations require an active connection.
	ErrNotConnected = errors.New("connection not established")
)

// Sender is the interface for sending data to the RC backend.
// Implementations should handle the actual network I/O.
type Sender interface {
	// Send transmits data to the RC backend.
	// Returns an error if the send fails.
	Send(ctx context.Context, data []byte) error
}

// SenderFunc is a function adapter that implements Sender.
type SenderFunc func(ctx context.Context, data []byte) error

func (f SenderFunc) Send(ctx context.Context, data []byte) error {
	return f(ctx, data)
}

// Client provides a high-level interface to the RC client library.
//
// It owns the event loop/runtime that drives internal execution, and caches of
// state (certificates, CRLs, etc) shared across all connections to the RC
// delivery backend. Each Client spawns a worker thread.
type Client struct {
	cCtx   *C.struct_Ctx
	mu     sync.RWMutex
	closed bool
}

// NewClient creates a new RC client.
//
// The client must be closed to free the underlying memory
func NewClient() *Client {
	c := &Client{cCtx: C.rc_init()}
	return c
}

// Close shuts down the client and releases all resources.
// All connections must be closed before calling this method.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	if c.cCtx != nil {
		C.rc_free(c.cCtx)
		c.cCtx = nil
	}
	return nil
}

// NewConnection creates a new connection to the RC backend.
//
// The connection must be closed to free the underlying memory
func (c *Client) NewConnection(sender Sender) (*ClientConnection, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, ErrClientClosed
	}

	if sender == nil {
		return nil, ErrNoSender
	}

	cc := &ClientConnection{
		conn:   C.rc_conn_new(c.cCtx),
		sender: sender,

		// setting it to a default to avoid nil pointer errors in Close	and
		// sendCallback before Connect is called. It will be overwritten in
		// Connect.
		ctx: context.Background(),
	}

	cc.handle = cgo.NewHandle(cc)

	C.rc_conn_send_callback(
		cc.conn,
		C.SendCb(C.goSendCallback),
		unsafe.Pointer(uintptr(cc.handle)), //nolint:unsafeptr // required by cgo.Handle docs
	)

	return cc, nil
}

// ClientConnection represents a connection to the RC backend with a high-level API.
//
// It brokers I/O between the client library and the FFI host runtime,
// modelling a single connection to the RC backend.
type ClientConnection struct {
	conn   *C.struct_FFIConnection
	sender Sender
	ctx    context.Context
	handle cgo.Handle

	mu        sync.RWMutex
	connected bool
	closed    bool
}

// sendCallback is the internal callback used by the C library.
func (cc *ClientConnection) sendCallback(data []byte) SendRet {
	cc.mu.RLock()
	sender := cc.sender
	ctx := cc.ctx
	closed := cc.closed
	defer cc.mu.RUnlock()

	if closed {
		return SendRetClosed
	}

	if err := sender.Send(ctx, data); err != nil {
		return SendRetUnknown
	}

	return SendRetSuccess
}

// Connect establishes the connection to the RC backend.
// The `ctx` is used for the duration of the connection and passed to the Sender on each send.
func (cc *ClientConnection) Connect(ctx context.Context) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.closed {
		return ErrConnectionClosed
	}

	if cc.connected {
		return nil
	}

	cc.ctx = ctx
	C.rc_conn_connected(cc.conn)
	cc.connected = true

	return nil
}

// Receive processes incoming data from the RC backend.
func (cc *ClientConnection) Receive(data []byte) error {
	cc.mu.RLock()
	connected := cc.connected
	closed := cc.closed
	defer cc.mu.RUnlock()

	if closed {
		return ErrConnectionClosed
	}

	if !connected {
		return ErrNotConnected
	}

	if len(data) == 0 {
		return io.ErrShortBuffer
	}

	ret := C.rc_conn_recv(
		cc.conn,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.uint32_t(len(data)),
	)

	if RecvRet(ret) != RecvRetSuccess {
		return fmt.Errorf("receive failed with code: %d", ret)
	}

	return nil
}

// Disconnect closes the connection to the RC backend.
//
// This call blocks until in-flight SendCallback calls are completed and the
// internal I/O task exits cleanly, after which time it is guaranteed no more
// calls to the SendCallback will be made.
func (cc *ClientConnection) Disconnect() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if !cc.connected {
		return nil
	}

	C.rc_conn_disconnected(cc.conn)
	cc.connected = false

	return nil
}

// Close releases all resources held by this connection.
// The connection must be disconnected before calling Close.
func (cc *ClientConnection) Close() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.closed {
		return nil
	}

	if cc.connected {
		return errors.New("connection must be disconnected before closing")
	}

	cc.closed = true

	if cc.conn != nil {
		cc.handle.Delete()

		C.rc_conn_free(cc.conn)
		cc.conn = nil
	}

	return nil
}

// IsConnected returns true if the connection is currently established.
func (cc *ClientConnection) IsConnected() bool {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.connected
}

// IsClosed returns true if the connection has been closed.
func (cc *ClientConnection) IsClosed() bool {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.closed
}
