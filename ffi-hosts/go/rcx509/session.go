package rcx509

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi"
	"github.com/coder/websocket"
)

const (
	// incomingQueueCap bounds how many frames read off the WebSocket may be
	// waiting on the FFI layer before the reader stops pulling from the socket
	incomingQueueCap = 100

	// writeTimeout bounds a single write to the RC backend
	writeTimeout = 10 * time.Second

	// defaultDialTimeout bounds how long a single connection attempt to the
	// RC backend may take before it is abandoned and retried.
	defaultDialTimeout = 10 * time.Second

	// defaultReadLimit overrides coder/websocket's own default of 32 KiB,
	// which is too small for RC payloads.
	defaultReadLimit = 1 << 20 // 1 MiB
)

type WebsocketDialer interface {
	Dial(ctx context.Context, url string, dialTimeout time.Duration) (WebsocketConnection, error)
}

type WebsocketConnection interface {
	Read(ctx context.Context) (websocket.MessageType, []byte, error)
	Write(ctx context.Context, typ websocket.MessageType, data []byte) error
	CloseNow() error
}

type CoderWebsocketDialer struct{}

func (cwd *CoderWebsocketDialer) Dial(ctx context.Context, url string, dialTimeout time.Duration) (WebsocketConnection, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	ws, _, err := websocket.Dial(dialCtx, url, nil)
	if err != nil {
		return nil, fmt.Errorf("rcx509: failed to dial %s: %w", url, err)
	}

	ws.SetReadLimit(defaultReadLimit)

	return ws, nil
}

// errNonBinaryFrame is returned by runSession when the RC backend sends a
// frame that is not a non-empty binary message. The FFI layer only ever
// carries protobuf-encoded payloads, so anything else means the peer is not
// speaking the RC protocol.
var errNonBinaryFrame = errors.New("rcx509: received a non-binary or empty frame")

// errFFIConnectionReleased is returned by runSession when the FFI layer closed
// the connection out from under the session, which happens when the Client's
// X509Context is closed while a session is running.
var errFFIConnectionReleased = errors.New("rcx509: FFI connection was released")

// runSession the entire lifecycle of an active connection between the x509 FFI
// backend and the RC backend.
//
// One call to runSession corresponds to exactly one FFIConnection: the FFI
// layer's connection lifecycle is terminal, so a fresh Connection must be
// created for every new WebSocket session rather than reused across
// reconnects.
func (c *Client) runSession(ctx context.Context) error {
	conn, ws, err := c.establishConnection(ctx)
	if err != nil {
		return err
	}

	// Concurrently read messages from the websocket, writing them to a channel
	// the main processing loop to handle
	incoming := make(chan []byte, incomingQueueCap)
	go func() {
		readWorker(ctx, ws, incoming)
	}()

	// Handle shutdown of the session. Inform the FFI layer that we are closing out the connection
	// and then drain the leftover messages and attempt to send them to the backen (on the chance
	// that we aren't closing due to a websocket issue)
	defer func() {
		// ??? Do we....really care here? Eventually we might want to log this.
		_ = conn.Disconnected()

		drainOutgoing(ctx, ws, conn.Outgoing())

		ws.CloseNow()
	}()

	// The main processing loop, handling messages from the Backend to the FFI, and from the
	// FFI to the backend until signaled to stop via our context, or until there is an issue
	// reading from the websocket (which will terminate the websocket conn) or the FFI layer
	// has closed the connection unexpectedly (which means we need to start over)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case msg, ok := <-incoming:
			if !ok {
				return nil
			}
			if err := conn.Recv(msg); err != nil {
				if errors.Is(err, libddrcffi.ErrConnectionClosed) ||
					errors.Is(err, libddrcffi.ErrConnectionNotConnected) {
					return fmt.Errorf("rcx509: failed to deliver message to FFI layer: %w", err)
				}
				log.Printf("rcx509: dropping message the FFI layer rejected: %v", err)
			}

		case msg, ok := <-conn.Outgoing():
			if !ok {
				return errFFIConnectionReleased
			}
			if err := writeMessage(ctx, ws, msg); err != nil {
				return fmt.Errorf("rcx509: websocket write failed: %w", err)
			}
		}
	}
}

// establishConnection creates a new FFI connection, dials the RC backend
// over a websocket, and marks the FFI connection as connected.
func (c *Client) establishConnection(ctx context.Context) (*libddrcffi.Connection, WebsocketConnection, error) {
	conn, err := c.ffiCtx.NewConnection()
	if err != nil {
		return nil, nil, fmt.Errorf("rcx509: failed to create FFI connection: %w", err)
	}

	ws, err := c.dialer.Dial(ctx, c.url, defaultDialTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("rcx509: failed to dial %s: %w", c.url, err)
	}

	if err := conn.Connected(); err != nil {
		return nil, nil, fmt.Errorf("rcx509: failed to mark FFI connection as connected: %w", err)
	}

	return conn, ws, nil
}

// readWorker reads messages from ws and passes the resulting byte slices over a channel
// for additional processing
//
// readWorker owns the messages channel, closing it when it returns to signal that no more
// messages will be added. readWorker runs until there is an error reading a message from
// the websocket, or its context signals completion.
func readWorker(ctx context.Context, ws WebsocketConnection, messages chan<- []byte) {
	defer close(messages)
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary || len(data) == 0 {
			return
		}

		select {
		case messages <- data:
		case <-ctx.Done():
			return
		}
	}
}

// drainOutgoing writes what is left on outgoing to ws until the FFI layer
// closes the channel, which it does once the connection has been freed.
//
// It's possible that we're shutting down not because of a websocket conn issue but because
// of some other internal issue. Any messages that have been processed by the x509 layer
// need responses, so we should make an attempt here.
//
// Note: This is a delicate dance, the ordering of how this is invoked matters, if this
// runs first and nothing concurrently calls Disconnect() on the FFI layer, this will block.
func drainOutgoing(ctx context.Context, ws WebsocketConnection, outgoing <-chan []byte) {
	writable := true
	for msg := range outgoing {
		if !writable {
			continue
		}
		if err := writeMessage(ctx, ws, msg); err != nil {
			log.Printf("rcx509: dropping outgoing payloads during teardown: %v", err)
			writable = false
		}
	}
}

// writeMessage writes a single binary message to ws under writeTimeout.
func writeMessage(ctx context.Context, ws WebsocketConnection, msg []byte) error {
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()

	return ws.Write(ctx, websocket.MessageBinary, msg)
}
