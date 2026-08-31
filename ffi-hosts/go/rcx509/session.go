package rcx509

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
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
	defaultReadLimit = 52428800 // 50 MiB
)

type WebsocketDialer interface {
	Dial(ctx context.Context, url string, dialTimeout time.Duration) (WebsocketConnection, error)
}

type WebsocketConnection interface {
	Read(ctx context.Context) (websocket.MessageType, []byte, error)
	Write(ctx context.Context, typ websocket.MessageType, data []byte) error
	CloseNow() error
}

// FFIContext is the subset of *libddrcffi.X509Context's behavior that the
// session lifecycle depends on.
type FFIContext interface {
	NewConnection() (FFIConnection, error)
	Close() error
}

// FFIConnection is the subset of *libddrcffi.Connection's behavior that the
// session lifecycle depends on.
type FFIConnection interface {
	Connected() error
	Close() error
	Recv(data []byte) error
	Outgoing() <-chan []byte
}

// ffiContext adapts *libddrcffi.X509Context to FFIContext. It exists because
// Go has no covariant returns: *libddrcffi.Connection already satisfies
// FFIConnection, but NewConnection's signature doesn't match FFIContext
// without this conversion.
type ffiContext struct {
	*libddrcffi.X509Context
}

func (f *ffiContext) NewConnection() (FFIConnection, error) {
	return f.X509Context.NewConnection()
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

// errEmptyPayload is returned when a payload is read from either the backend or
// the FFI layer that is empty, we should never have empty payloads based on the protocol
var errEmptyPayload = errors.New("rcx509: received an empty payload")

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

	// websocket read operations block, and we also need to be managing messages
	// from the rc-x509-client layer that we need to send to the backend, so run
	// a worker to queue up incoming messages for us on a channel.
	incoming := make(chan []byte, incomingQueueCap)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		err := readWorker(ctx, ws, incoming)
		if err != nil && ctx.Err() == nil {
			log.Printf("rcx509: read worker quit for read error: %v", err)
		}
		wg.Done()
	}()

	// Shutdown operations to ensure we clean up
	defer func() {
		err = conn.Close()
		if err != nil {
			// We need to do the other operations, so log this and move on
			log.Printf("rcx509: error disconnecting connection to rc-x509-client layer: %v", err)
		}

		// Attempt to send any pending message to the backend, if this shutdown operation wasn't due
		// to an issue with the websocket connection.
		//
		// Note: We must use a drain specific conterxt here in the event this is happening because
		// the parent ctx associated with this Client has told us to shutdown.
		drainCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		drainOutgoing(drainCtx, ws, conn.Outgoing())
		cancel()

		// Finally, force close the websocket connection, which will trigger closing of our
		// readWorker if this shutdown is due to some unforseen issue from the rc-x509-client layer
		ws.CloseNow()
		wg.Wait()
	}()

	// The main processing loop managing incoming and outgoing messages.
	for {
		select {
		// We are being instructed to shutdown by the system.
		case <-ctx.Done():
			return ctx.Err()

		// There is a messages from the RC backend we need to push to the rc-x509-client layer
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

		// There is a message from the rc-x509-client layer we need to push to the backend
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
func (c *Client) establishConnection(ctx context.Context) (FFIConnection, WebsocketConnection, error) {
	conn, err := c.ffiCtx.NewConnection()
	if err != nil {
		return nil, nil, fmt.Errorf("rcx509: failed to create FFI connection: %w", err)
	}

	ws, err := c.dialer.Dial(ctx, c.url, defaultDialTimeout)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("rcx509: failed to dial %s: %w", c.url, err)
	}

	if err := conn.Connected(); err != nil {
		conn.Close()
		_ = ws.CloseNow()
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
func readWorker(ctx context.Context, ws WebsocketConnection, messages chan<- []byte) error {
	defer close(messages)
	for {
		message, err := readMessage(ctx, ws)
		if err != nil {
			return err
		}

		select {
		case messages <- message:
		case <-ctx.Done():
			return ctx.Err()
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

// readMessage reads exactly one message from the provided websocket.
//
// readMessage only accepts binary messages, as that is the only type of messages
// that any RC backend should be speaking.
func readMessage(ctx context.Context, ws WebsocketConnection) ([]byte, error) {
	typ, data, err := ws.Read(ctx)
	if err != nil {
		return nil, err
	}

	if typ != websocket.MessageBinary {
		return nil, errNonBinaryFrame
	}

	if len(data) == 0 {
		return nil, errEmptyPayload
	}

	return data, nil
}

// writeMessage writes a single binary message to ws under writeTimeout.
func writeMessage(ctx context.Context, ws WebsocketConnection, msg []byte) error {
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()

	return ws.Write(ctx, websocket.MessageBinary, msg)
}
