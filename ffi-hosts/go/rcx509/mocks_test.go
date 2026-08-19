package rcx509

import (
	"context"
	"errors"
	"time"

	"github.com/coder/websocket"
)

type fakeWebsocketDialer struct {
	conn      WebsocketConnection
	dialErr   error
	dialCount int
}

func (fd *fakeWebsocketDialer) Dial(ctx context.Context, url string, dialTimeout time.Duration) (WebsocketConnection, error) {
	fd.dialCount++
	if fd.dialErr != nil {
		return nil, fd.dialErr
	}
	return fd.conn, nil
}

type message struct {
	typ  websocket.MessageType
	data []byte
	err  error
}

type fakeWebsocketConn struct {
	incomingMessages  chan message
	outgoingMessages  chan message
	forceWriteError   bool
	writeErr          error
	writeAttempts     int
	lastAttemptedData []byte
	closeNowCalls     int
	closed            chan struct{}
}

func (fc *fakeWebsocketConn) Read(ctx context.Context) (typ websocket.MessageType, data []byte, err error) {
	for {
		select {
		case message, ok := <-fc.incomingMessages:
			if !ok {
				return websocket.MessageBinary, nil, errors.New("incoming closed")
			}
			return message.typ, message.data, message.err
		case <-ctx.Done():
			return websocket.MessageBinary, nil, ctx.Err()
		case <-fc.closed:
			return websocket.MessageBinary, nil, errors.New("connection closed")
		}
	}
}

func (fc *fakeWebsocketConn) Write(ctx context.Context, typ websocket.MessageType, data []byte) error {
	fc.writeAttempts++
	fc.lastAttemptedData = data

	if fc.writeErr != nil {
		return fc.writeErr
	}

	if fc.forceWriteError {
		return errors.New("write failed")
	}

	if err := ctx.Err(); err != nil {
		close(fc.outgoingMessages)
		return err
	}

	select {
	case fc.outgoingMessages <- message{typ: typ, data: data, err: nil}:
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

// CloseNow mimics coder/websocket's behavior of aborting any in-flight Read
// once the connection is closed, which runSession's cleanup relies on to let
// the readWorker goroutine exit.
func (fc *fakeWebsocketConn) CloseNow() error {
	fc.closeNowCalls++
	select {
	case <-fc.closed:
	default:
		close(fc.closed)
	}
	return nil
}

func newFakeWebsocketConn() *fakeWebsocketConn {
	return &fakeWebsocketConn{
		incomingMessages: make(chan message, 100),
		outgoingMessages: make(chan message, 100),
		closed:           make(chan struct{}),
	}
}

type fakeFFIContext struct {
	conn         FFIConnection
	newConnErr   error
	closeErr     error
	newConnCalls int
}

func (fc *fakeFFIContext) NewConnection() (FFIConnection, error) {
	fc.newConnCalls++
	if fc.newConnErr != nil {
		return nil, fc.newConnErr
	}
	return fc.conn, nil
}

func (fc *fakeFFIContext) Close() error {
	return fc.closeErr
}

type fakeFFIConnection struct {
	received chan []byte
	outgoing chan []byte

	connectedErr    error
	disconnectedErr error
	recvErr         error

	disconnectedCalls int
	outgoingClosed    bool
}

func (fc *fakeFFIConnection) Connected() error {
	return fc.connectedErr
}

// Disconnected mimics libddrcffi.Connection.Disconnected's contract: outgoing
// is closed before returning regardless of whether an error is reported.
func (fc *fakeFFIConnection) Disconnected() error {
	fc.disconnectedCalls++
	if !fc.outgoingClosed {
		fc.outgoingClosed = true
		close(fc.outgoing)
	}
	return fc.disconnectedErr
}

func (fc *fakeFFIConnection) Recv(data []byte) error {
	fc.received <- data
	return fc.recvErr
}

func (fc *fakeFFIConnection) Outgoing() <-chan []byte {
	return fc.outgoing
}

// closeOutgoing simulates the FFI layer releasing the connection on its own,
// independent of Disconnected being called.
func (fc *fakeFFIConnection) closeOutgoing() {
	if !fc.outgoingClosed {
		fc.outgoingClosed = true
		close(fc.outgoing)
	}
}

func newFakeFFIConnection() *fakeFFIConnection {
	return &fakeFFIConnection{
		received: make(chan []byte, 100),
		outgoing: make(chan []byte, 100),
	}
}
