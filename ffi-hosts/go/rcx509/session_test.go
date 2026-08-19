package rcx509

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi"
	"github.com/coder/websocket"
)

type message struct {
	typ  websocket.MessageType
	data []byte
}

type fakeWebsocketConn struct {
	incomingMessages []message
	outgoingMessages []message
}

func (fc *fakeWebsocketConn) Read(ctx context.Context) (typ websocket.MessageType, data []byte, err error) {
	if len(fc.incomingMessages) == 0 {
		return websocket.MessageBinary, nil, errors.New("no more messages")
	}

	next := fc.incomingMessages[0]

	fc.incomingMessages = fc.incomingMessages[1:]

	return next.typ, next.data, nil
}

func (fc *fakeWebsocketConn) Write(ctx context.Context, typ websocket.MessageType, data []byte) error {
	if len(fc.outgoingMessages) == cap(fc.outgoingMessages) {
		return errors.New("write failed")
	}

	fc.outgoingMessages = append(fc.outgoingMessages, message{typ: typ, data: data})

	return nil
}

func (fc *fakeWebsocketConn) CloseNow() error {
	return nil
}

func newFakeWebsocketConn() *fakeWebsocketConn {
	return &fakeWebsocketConn{}
}

// TestReadWorkerRejectsMessageTypeText verifies that the read worker
// aborts if a text message is sent, which is not part of the RC x509 protocol.
func TestReadWorkerRejectsMessageTypeText(t *testing.T) {
	conn := newFakeWebsocketConn()

	conn.incomingMessages = append(conn.incomingMessages, message{typ: websocket.MessageText, data: []byte("hi")})

	readMessages := make(chan []byte)

	readWorker(context.Background(), conn, readMessages)

	// readWorker should close without reading a message
	_, ok := <-readMessages
	if ok {
		t.Error("readWorker should not process any non websocket.MessageBinary messages")
	}
}

// TestReadWorkerReadsMessages verifies that the read worker forwards every
// binary message it reads off the websocket, in order, before closing the
// channel once the connection runs out of messages.
func TestReadWorkerReadsMessages(t *testing.T) {
	conn := newFakeWebsocketConn()

	conn.incomingMessages = append(conn.incomingMessages,
		message{typ: websocket.MessageBinary, data: []byte("first")},
		message{typ: websocket.MessageBinary, data: []byte("second")},
	)

	readMessages := make(chan []byte, 2)

	readWorker(context.Background(), conn, readMessages)

	first := <-readMessages
	if string(first) != "first" {
		t.Errorf("expected first message %q, got %q", "first", first)
	}

	second := <-readMessages
	if string(second) != "second" {
		t.Errorf("expected second message %q, got %q", "second", second)
	}

	if _, ok := <-readMessages; ok {
		t.Error("readWorker should close readMessages once it runs out of messages")
	}
}

// TestDrainOutgoingWritesAllMessages verifies that drainOutgoing writes every
// message it drains from outgoing to the websocket.
func TestDrainOutgoingWritesAllMessages(t *testing.T) {
	conn := newFakeWebsocketConn()
	conn.outgoingMessages = make([]message, 0, 2)

	outgoing := make(chan []byte, 2)
	outgoing <- []byte("first")
	outgoing <- []byte("second")
	close(outgoing)

	drainOutgoing(context.Background(), conn, outgoing)

	if len(conn.outgoingMessages) != 2 {
		t.Fatalf("expected 2 messages written, got %d", len(conn.outgoingMessages))
	}
	if string(conn.outgoingMessages[0].data) != "first" {
		t.Errorf("expected first message %q, got %q", "first", conn.outgoingMessages[0].data)
	}
	if string(conn.outgoingMessages[1].data) != "second" {
		t.Errorf("expected second message %q, got %q", "second", conn.outgoingMessages[1].data)
	}
}

// TestDrainOutgoingStopsWritingAfterError verifies that once a write fails,
// drainOutgoing keeps draining outgoing but stops writing to the websocket.
func TestDrainOutgoingStopsWritingAfterError(t *testing.T) {
	conn := newFakeWebsocketConn()
	conn.outgoingMessages = make([]message, 0, 1)

	outgoing := make(chan []byte, 3)
	outgoing <- []byte("first")
	outgoing <- []byte("second")
	outgoing <- []byte("third")
	close(outgoing)

	drainOutgoing(context.Background(), conn, outgoing)

	if len(conn.outgoingMessages) != 1 {
		t.Fatalf("expected only 1 message written, got %d", len(conn.outgoingMessages))
	}
	if string(conn.outgoingMessages[0].data) != "first" {
		t.Errorf("expected first message %q, got %q", "first", conn.outgoingMessages[0].data)
	}

	_, ok := <-outgoing
	if ok {
		t.Errorf("drainOutgoing should leave no more messages on the channel")
	}
}

type fakeWebsocketDialer struct {
	conn WebsocketConnection
}

func (fd *fakeWebsocketDialer) Dial(ctx context.Context, url string, dialTimeout time.Duration) (WebsocketConnection, error) {
	return fd.conn, nil
}

// TestRunSessionShutsDownOnReadClose verifies that runSession reads a
// message off the websocket, delivers it to the FFI layer, and then returns
// once the websocket connection closes.
func TestRunSessionShutsDownOnReadClose(t *testing.T) {
	ffiCtx, err := libddrcffi.Init()
	if err != nil {
		t.Fatalf("libddrcffi.Init() returned error: %v", err)
	}
	defer ffiCtx.Close()

	conn := newFakeWebsocketConn()
	conn.incomingMessages = append(conn.incomingMessages, message{typ: websocket.MessageBinary, data: []byte("hello")})
	conn.outgoingMessages = make([]message, 0, 10)

	client := &Client{
		ffiCtx: ffiCtx,
		url:    "ws://example.com",
		dialer: &fakeWebsocketDialer{conn: conn},
	}

	if err := client.runSession(context.Background()); err != nil {
		t.Fatalf("runSession returned unexpected error: %v", err)
	}

	if len(conn.incomingMessages) != 0 {
		t.Error("expected runSession to read the single incoming message")
	}
}
