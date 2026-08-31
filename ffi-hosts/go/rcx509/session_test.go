package rcx509

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi"
	"github.com/coder/websocket"
)

// TestReadWorkerRejectsMessageTypeText verifies that the read worker
// aborts if a text message is sent, which is not part of the RC x509 protocol.
func TestReadWorkerRejectsMessageTypeText(t *testing.T) {
	conn := newFakeWebsocketConn()
	readMessages := make(chan []byte)

	errCh := make(chan error, 1)
	go func() {
		errCh <- readWorker(context.Background(), conn, readMessages)
	}()

	// Invalid websocket message type
	conn.incomingMessages <- message{typ: websocket.MessageText, data: []byte("hi")}

	// readWorker should close without reading a message
	select {
	case _, ok := <-readMessages:
		if ok {
			t.Error("readWorker should not process any non websocket.MessageBinary messages")
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout")
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, errNonBinaryFrame) {
			t.Errorf("expected errNonBinaryFrame, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for readWorker to return")
	}
}

// TestReadWorkerRejectsEmptyPayload verifies that the read worker aborts if
// an empty binary message is sent, which is not part of the RC x509 protocol.
func TestReadWorkerRejectsEmptyPayload(t *testing.T) {
	conn := newFakeWebsocketConn()
	readMessages := make(chan []byte)

	errCh := make(chan error, 1)
	go func() {
		errCh <- readWorker(context.Background(), conn, readMessages)
	}()

	conn.incomingMessages <- message{typ: websocket.MessageBinary, data: []byte{}}

	// readWorker should close without reading a message
	select {
	case _, ok := <-readMessages:
		if ok {
			t.Error("readWorker should not process any empty payloads")
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout")
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, errEmptyPayload) {
			t.Errorf("expected errEmptyPayload, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for readWorker to return")
	}
}

// TestReadWorkerKicksOutOnReadError verifies that the read worker aborts if
// the underlying websocket read fails.
func TestReadWorkerKicksOutOnReadError(t *testing.T) {
	conn := newFakeWebsocketConn()
	readMessages := make(chan []byte)

	readErr := errors.New("read failure")
	conn.incomingMessages <- message{typ: websocket.MessageBinary, data: nil, err: readErr}
	err := readWorker(context.Background(), conn, readMessages)

	if !errors.Is(err, readErr) {
		t.Errorf("expected %v, got %v", readErr, err)
	}

	// readWorker should close without reading a message
	select {
	case _, ok := <-readMessages:
		if ok {
			t.Error("readWorker should not process any messages after a read error")
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout")
	}
}

// TestReadMessageRejectsNonBinaryFrame verifies that readMessage returns
// errNonBinaryFrame when the websocket yields a non-binary message.
func TestReadMessageRejectsNonBinaryFrame(t *testing.T) {
	conn := newFakeWebsocketConn()
	conn.incomingMessages <- message{typ: websocket.MessageText, data: []byte("hi")}

	_, err := readMessage(context.Background(), conn)
	if !errors.Is(err, errNonBinaryFrame) {
		t.Errorf("expected errNonBinaryFrame, got %v", err)
	}
}

// TestReadMessageRejectsEmptyPayload verifies that readMessage returns
// errEmptyPayload when the websocket yields a binary message with no data.
func TestReadMessageRejectsEmptyPayload(t *testing.T) {
	conn := newFakeWebsocketConn()
	conn.incomingMessages <- message{typ: websocket.MessageBinary, data: []byte{}}

	_, err := readMessage(context.Background(), conn)
	if !errors.Is(err, errEmptyPayload) {
		t.Errorf("expected errEmptyPayload, got %v", err)
	}
}

// TestReadMessageReturnsBinaryPayload verifies that readMessage returns the
// payload of a valid binary message unchanged.
func TestReadMessageReturnsBinaryPayload(t *testing.T) {
	conn := newFakeWebsocketConn()
	conn.incomingMessages <- message{typ: websocket.MessageBinary, data: []byte("hello")}

	data, err := readMessage(context.Background(), conn)
	if err != nil {
		t.Fatalf("readMessage returned unexpected error: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("expected message %q, got %q", "hello", data)
	}
}

// TestReadMessagePropagatesReadError verifies that readMessage returns
// whatever error the underlying websocket read produces, unwrapped.
func TestReadMessagePropagatesReadError(t *testing.T) {
	conn := newFakeWebsocketConn()
	readErr := errors.New("boom")
	conn.incomingMessages <- message{typ: websocket.MessageBinary, data: nil, err: readErr}

	_, err := readMessage(context.Background(), conn)
	if !errors.Is(err, readErr) {
		t.Errorf("expected %v, got %v", readErr, err)
	}
}

// TestReadWorkerReadsMessages verifies that the read worker forwards every
// binary message it reads off the websocket, in order, before closing the
// channel once the connection runs out of messages.
func TestReadWorkerReadsMessages(t *testing.T) {
	conn := newFakeWebsocketConn()
	// Buffered to fit both messages, so readWorker never blocks trying to
	// deliver one and can run synchronously below.
	readMessages := make(chan []byte, 2)

	conn.incomingMessages <- message{typ: websocket.MessageBinary, data: []byte("first")}
	conn.incomingMessages <- message{typ: websocket.MessageBinary, data: []byte("second")}
	close(conn.incomingMessages)

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

// TestReadWorkerReturnsContextErrorWhenCanceled verifies that readWorker
// reports context cancellation as an error rather than swallowing it to allow
// downstream callers to ignore cancellation and not log spurious errors
func TestReadWorkerReturnsContextErrorWhenCanceled(t *testing.T) {
	conn := newFakeWebsocketConn()
	conn.incomingMessages <- message{typ: websocket.MessageBinary, data: []byte("hello")}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	readMessages := make(chan []byte)

	err := readWorker(ctx, conn, readMessages)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	if _, ok := <-readMessages; ok {
		t.Error("readWorker should not deliver a message once ctx is canceled")
	}
}

// TestDrainOutgoingWritesAllMessages verifies that drainOutgoing writes every
// message it drains from outgoing to the websocket.
func TestDrainOutgoingWritesAllMessages(t *testing.T) {
	conn := newFakeWebsocketConn()

	// Populate the outgoing messages
	outgoing := make(chan []byte, 2)
	outgoing <- []byte("first")
	outgoing <- []byte("second")
	close(outgoing)

	drainOutgoing(context.Background(), conn, outgoing)

	if len(conn.outgoingMessages) != 2 {
		t.Fatalf("expected 2 messages written, got %d", len(conn.outgoingMessages))
	}

	m1 := <-conn.outgoingMessages
	if m1.typ != websocket.MessageBinary {
		t.Errorf("expected type of MessageBinary, got %q", m1.typ)
	}
	if string(m1.data) != "first" {
		t.Errorf("expected first message %q, got %q", "first", m1.data)
	}

	m2 := <-conn.outgoingMessages
	if m2.typ != websocket.MessageBinary {
		t.Errorf("expected type of MessageBinary, got %q", m1.typ)
	}
	if string(m2.data) != "second" {
		t.Errorf("expected first message %q, got %q", "second", m2.data)
	}
}

// TestDrainOutgoingStopsWritingAfterError verifies that once a write fails,
// drainOutgoing keeps draining outgoing but stops attempting further writes.
func TestDrainOutgoingStopsWritingAfterError(t *testing.T) {
	conn := newFakeWebsocketConn()
	conn.forceWriteError = true

	outgoing := make(chan []byte, 3)
	outgoing <- []byte("first")
	outgoing <- []byte("second")
	outgoing <- []byte("third")
	close(outgoing)

	drainOutgoing(context.Background(), conn, outgoing)

	if conn.writeAttempts != 1 {
		t.Fatalf("expected exactly 1 write attempt, got %d", conn.writeAttempts)
	}
	if string(conn.lastAttemptedData) != "first" {
		t.Fatalf("expected write attempt for %q, got %q", "first", conn.lastAttemptedData)
	}

	if len(conn.outgoingMessages) != 0 {
		t.Fatalf("expected no messages written, got %d", len(conn.outgoingMessages))
	}

	if _, ok := <-outgoing; ok {
		t.Error("drainOutgoing should leave no more messages on the channel")
	}
}

// TestEstablishConnectionReturnsErrorWhenNewConnectionFails verifies that
// establishConnection never dials the backend if it can't create an FFI
// connection in the first place.
func TestEstablishConnectionReturnsErrorWhenNewConnectionFails(t *testing.T) {
	newConnErr := errors.New("boom")
	client := &Client{
		ffiCtx: &fakeFFIContext{newConnErr: newConnErr},
		url:    "ws://example.com",
		dialer: &fakeWebsocketDialer{conn: newFakeWebsocketConn()},
	}

	conn, ws, err := client.establishConnection(context.Background())
	if !errors.Is(err, newConnErr) {
		t.Errorf("expected %v, got %v", newConnErr, err)
	}
	if conn != nil || ws != nil {
		t.Error("expected establishConnection to return nil conn and ws on failure")
	}

	dialer := client.dialer.(*fakeWebsocketDialer)
	if dialer.dialCount != 0 {
		t.Errorf("expected dialer not to be called, got %d calls", dialer.dialCount)
	}
}

// TestEstablishConnectionReleasesFFIConnectionWhenDialFails verifies that
// establishConnection releases the FFI connection it created if dialing the
// websocket backend fails, so the FFI connection isn't leaked.
func TestEstablishConnectionReleasesFFIConnectionWhenDialFails(t *testing.T) {
	dialErr := errors.New("dial boom")
	ffiConn := newFakeFFIConnection()
	client := &Client{
		ffiCtx: &fakeFFIContext{conn: ffiConn},
		url:    "ws://example.com",
		dialer: &fakeWebsocketDialer{dialErr: dialErr},
	}

	conn, ws, err := client.establishConnection(context.Background())
	if !errors.Is(err, dialErr) {
		t.Errorf("expected %v, got %v", dialErr, err)
	}
	if conn != nil || ws != nil {
		t.Error("expected establishConnection to return nil conn and ws on failure")
	}

	if ffiConn.disconnectedCalls != 1 {
		t.Errorf("expected FFI connection to be released exactly once, got %d calls", ffiConn.disconnectedCalls)
	}
}

// TestEstablishConnectionCleansUpWhenConnectedFails verifies that
// establishConnection both closes the websocket it dialed and releases the
// FFI connection it created if marking the FFI connection as connected
// fails, so neither is leaked.
func TestEstablishConnectionCleansUpWhenConnectedFails(t *testing.T) {
	connectedErr := errors.New("connected boom")
	ffiConn := newFakeFFIConnection()
	ffiConn.connectedErr = connectedErr
	ws := newFakeWebsocketConn()
	client := &Client{
		ffiCtx: &fakeFFIContext{conn: ffiConn},
		url:    "ws://example.com",
		dialer: &fakeWebsocketDialer{conn: ws},
	}

	conn, gotWS, err := client.establishConnection(context.Background())
	if !errors.Is(err, connectedErr) {
		t.Errorf("expected %v, got %v", connectedErr, err)
	}
	if conn != nil || gotWS != nil {
		t.Error("expected establishConnection to return nil conn and ws on failure")
	}

	if ws.closeNowCalls != 1 {
		t.Errorf("expected websocket to be closed exactly once, got %d calls", ws.closeNowCalls)
	}
	if ffiConn.disconnectedCalls != 1 {
		t.Errorf("expected FFI connection to be released exactly once, got %d calls", ffiConn.disconnectedCalls)
	}
}

// TestEstablishConnectionSucceeds verifies that establishConnection returns
// the FFI connection and websocket it created without tearing either down
// when nothing fails.
func TestEstablishConnectionSucceeds(t *testing.T) {
	ffiConn := newFakeFFIConnection()
	ws := newFakeWebsocketConn()
	client := &Client{
		ffiCtx: &fakeFFIContext{conn: ffiConn},
		url:    "ws://example.com",
		dialer: &fakeWebsocketDialer{conn: ws},
	}

	conn, gotWS, err := client.establishConnection(context.Background())
	if err != nil {
		t.Fatalf("establishConnection returned unexpected error: %v", err)
	}
	if conn != ffiConn {
		t.Error("expected establishConnection to return the FFI connection it created")
	}
	if gotWS != ws {
		t.Error("expected establishConnection to return the websocket it dialed")
	}

	if ws.closeNowCalls != 0 {
		t.Errorf("expected websocket not to be closed, got %d calls", ws.closeNowCalls)
	}
	if ffiConn.disconnectedCalls != 0 {
		t.Errorf("expected FFI connection not to be released, got %d calls", ffiConn.disconnectedCalls)
	}
}

// TestRunSessionShutsDownOnReadClose verifies that runSession reads a
// message off the websocket, delivers it to the FFI layer, and then returns
// once the websocket connection closes.
func TestRunSessionShutsDownOnReadClose(t *testing.T) {
	ws := newFakeWebsocketConn()
	ws.incomingMessages <- message{typ: websocket.MessageBinary, data: []byte("hello")}
	close(ws.incomingMessages)

	ffiConn := newFakeFFIConnection()
	client := &Client{
		ffiCtx: &fakeFFIContext{conn: ffiConn},
		url:    "ws://example.com",
		dialer: &fakeWebsocketDialer{conn: ws},
	}

	if err := client.runSession(context.Background()); err != nil {
		t.Fatalf("runSession returned unexpected error: %v", err)
	}

	select {
	case data := <-ffiConn.received:
		if string(data) != "hello" {
			t.Errorf("expected received message %q, got %q", "hello", data)
		}
	default:
		t.Error("expected runSession to deliver the incoming message to the FFI layer")
	}
}

// TestRunSessionHappyPath verifies that runSession
// establishes a connection exactly once, moves messages in both directions,
// and fully tears down the FFI connection and websocket once the context is
// canceled.
func TestRunSessionHappyPath(t *testing.T) {
	ws := newFakeWebsocketConn()
	ffiConn := newFakeFFIConnection()
	ffiCtx := &fakeFFIContext{conn: ffiConn}
	dialer := &fakeWebsocketDialer{conn: ws}
	client := &Client{
		ffiCtx: ffiCtx,
		url:    "ws://example.com",
		dialer: dialer,
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.runSession(ctx)
	}()

	// Backend -> FFI layer
	ws.incomingMessages <- message{typ: websocket.MessageBinary, data: []byte("from backend")}
	select {
	case data := <-ffiConn.received:
		if string(data) != "from backend" {
			t.Errorf("expected received message %q, got %q", "from backend", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for message to reach the FFI layer")
	}

	// FFI layer -> backend
	ffiConn.outgoing <- []byte("from ffi")
	select {
	case m := <-ws.outgoingMessages:
		if string(m.data) != "from ffi" {
			t.Errorf("expected outgoing message %q, got %q", "from ffi", m.data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for message to reach the websocket")
	}

	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for runSession to return")
	}

	if ffiCtx.newConnCalls != 1 {
		t.Errorf("expected exactly 1 call to NewConnection, got %d", ffiCtx.newConnCalls)
	}
	if dialer.dialCount != 1 {
		t.Errorf("expected exactly 1 dial attempt, got %d", dialer.dialCount)
	}
	if ffiConn.disconnectedCalls != 1 {
		t.Errorf("expected FFI connection to be disconnected exactly once, got %d calls", ffiConn.disconnectedCalls)
	}
	if ws.closeNowCalls != 1 {
		t.Errorf("expected websocket to be closed exactly once, got %d calls", ws.closeNowCalls)
	}
}

// TestRunSessionTerminatesOnMessageLoopErrors verifies that runSession
// returns the expected error for each way the message loop can end besides
// context cancellation, and that it still fully cleans up the FFI connection
// and websocket in every case.
func TestRunSessionTerminatesOnMessageLoopErrors(t *testing.T) {
	writeErr := errors.New("write boom")

	tests := []struct {
		name    string
		setup   func(ffiConn *fakeFFIConnection, ws *fakeWebsocketConn)
		trigger func(ffiConn *fakeFFIConnection, ws *fakeWebsocketConn)
		wantErr error // nil means runSession must return exactly nil
	}{
		{
			name: "RecvFatalErrorTerminatesSession",
			setup: func(ffiConn *fakeFFIConnection, ws *fakeWebsocketConn) {
				ffiConn.recvErr = libddrcffi.ErrConnectionClosed
			},
			trigger: func(ffiConn *fakeFFIConnection, ws *fakeWebsocketConn) {
				ws.incomingMessages <- message{typ: websocket.MessageBinary, data: []byte("hello")}
			},
			wantErr: libddrcffi.ErrConnectionClosed,
		},
		{
			name: "OutgoingChannelReleasedByFFILayer",
			trigger: func(ffiConn *fakeFFIConnection, ws *fakeWebsocketConn) {
				ffiConn.closeOutgoing()
			},
			wantErr: errFFIConnectionReleased,
		},
		{
			name: "WebsocketWriteFailureTerminatesSession",
			setup: func(ffiConn *fakeFFIConnection, ws *fakeWebsocketConn) {
				ws.writeErr = writeErr
			},
			trigger: func(ffiConn *fakeFFIConnection, ws *fakeWebsocketConn) {
				ffiConn.outgoing <- []byte("outbound")
			},
			wantErr: writeErr,
		},
		{
			name: "ReadWorkerErrorClosesIncomingChannel",
			trigger: func(ffiConn *fakeFFIConnection, ws *fakeWebsocketConn) {
				close(ws.incomingMessages)
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws := newFakeWebsocketConn()
			ffiConn := newFakeFFIConnection()
			if tt.setup != nil {
				tt.setup(ffiConn, ws)
			}

			client := &Client{
				ffiCtx: &fakeFFIContext{conn: ffiConn},
				url:    "ws://example.com",
				dialer: &fakeWebsocketDialer{conn: ws},
			}

			errCh := make(chan error, 1)
			go func() {
				errCh <- client.runSession(context.Background())
			}()

			tt.trigger(ffiConn, ws)

			select {
			case err := <-errCh:
				if tt.wantErr == nil {
					if err != nil {
						t.Errorf("expected nil error, got %v", err)
					}
				} else if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected %v, got %v", tt.wantErr, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for runSession to return")
			}

			if ffiConn.disconnectedCalls != 1 {
				t.Errorf("expected FFI connection to be disconnected exactly once, got %d calls", ffiConn.disconnectedCalls)
			}
			if ws.closeNowCalls != 1 {
				t.Errorf("expected websocket to be closed exactly once, got %d calls", ws.closeNowCalls)
			}
		})
	}
}

// TestRunSessionDropsMessageOnTransientRecvError verifies that a non-fatal
// error from delivering a message to the FFI layer is logged and dropped
// without terminating the session, so subsequent messages continue to be
// processed.
func TestRunSessionDropsMessageOnTransientRecvError(t *testing.T) {
	ws := newFakeWebsocketConn()
	ffiConn := newFakeFFIConnection()
	ffiConn.recvErr = errors.New("transient recv failure")

	client := &Client{
		ffiCtx: &fakeFFIContext{conn: ffiConn},
		url:    "ws://example.com",
		dialer: &fakeWebsocketDialer{conn: ws},
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.runSession(ctx)
	}()

	ws.incomingMessages <- message{typ: websocket.MessageBinary, data: []byte("first")}
	select {
	case data := <-ffiConn.received:
		if string(data) != "first" {
			t.Errorf("expected received message %q, got %q", "first", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for first message to reach the FFI layer")
	}

	// The session should still be running after the transient error: a
	// second message must still make it through.
	ws.incomingMessages <- message{typ: websocket.MessageBinary, data: []byte("second")}
	select {
	case data := <-ffiConn.received:
		if string(data) != "second" {
			t.Errorf("expected received message %q, got %q", "second", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for second message to reach the FFI layer; session may have terminated early")
	}

	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for runSession to return")
	}
}
