package ddrc

import (
	"errors"
	"testing"
)

// TestContextLifecycle verifies that we can create, and close a
// context. (It should always succeed both operations when used like
// this.)
func TestContextLifecycle(t *testing.T) {
	ctx, err := Init()
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}
	if ctx == nil {
		t.Fatal("Init() returned a nil context")
	}

	if err := ctx.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
}

// TestContextCloseTwice verifies that if we try to
// close a context after already closing it, we properly
// get a ErrContextClosed.
func TestContextCloseTwice(t *testing.T) {
	ctx, err := Init()
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}

	if err := ctx.Close(); err != nil {
		t.Fatalf("first Close() returned error: %v", err)
	}

	if err := ctx.Close(); !errors.Is(err, ErrContextClosed) {
		t.Fatalf("second Close() = %v, want ErrContextClosed", err)
	}
}

// TestConnectionLifecycle drives the full FFI connection lifecycle, although
// at the moment, since the rx-x509-client just echoes messages it receives,
// it just ensures that nothing crashes when we attempt to exercise a connection.
func TestConnectionLifecycle(t *testing.T) {
	ctx, err := Init()
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}

	conn, err := ctx.NewConnection()
	if err != nil {
		t.Fatalf("NewConnection() returned error: %v", err)
	}

	if err := conn.Connected(); err != nil {
		t.Fatalf("Connected() returned error: %v", err)
	}

	if err := conn.Recv([]byte{0x01, 0x02, 0x03}); err != nil {
		t.Fatalf("Recv() returned error: %v", err)
	}

	if err := conn.Disconnected(); err != nil {
		t.Fatalf("Disconnected() returned error: %v", err)
	}

	if err := ctx.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
}

// TestContextCloseWithOpenConnection verifies Close refuses to release the
// context while a connection created from it is still open. rc_free requires
// every connection be freed beforehand, and using a connection that outlived
// its context aborts the process.
func TestContextCloseWithOpenConnection(t *testing.T) {
	ctx, err := Init()
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}

	conn, err := ctx.NewConnection()
	if err != nil {
		t.Fatalf("NewConnection() returned error: %v", err)
	}
	if err := conn.Connected(); err != nil {
		t.Fatalf("Connected() returned error: %v", err)
	}

	if err := ctx.Close(); !errors.Is(err, ErrConnectionsOpen) {
		t.Fatalf("Close() = %v, want ErrConnectionsOpen", err)
	}

	if err := conn.Disconnected(); err != nil {
		t.Fatalf("Disconnected() returned error: %v", err)
	}

	// Releasing the last connection lets the context close.
	if err := ctx.Close(); err != nil {
		t.Fatalf("Close() after Disconnected() returned error: %v", err)
	}
}

// TestConnectionDisconnectedWithoutConnected verifies that calling
// Disconnected on a Connection that Connected was never called on returns
// ErrConnectionNotConnected rather than crashing, while still freeing the
// connection's resources.
func TestConnectionDisconnectedWithoutConnected(t *testing.T) {
	ctx, err := Init()
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}
	defer func() { _ = ctx.Close() }()

	conn, err := ctx.NewConnection()
	if err != nil {
		t.Fatalf("NewConnection() returned error: %v", err)
	}

	if err := conn.Disconnected(); !errors.Is(err, ErrConnectionNotConnected) {
		t.Fatalf("Disconnected() = %v, want ErrConnectionNotConnected", err)
	}

	if err := conn.Disconnected(); !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("second Disconnected() = %v, want ErrConnectionClosed", err)
	}
}
