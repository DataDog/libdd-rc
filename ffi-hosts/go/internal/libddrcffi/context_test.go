package libddrcffi

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

	if err := conn.Close(); err != nil {
		t.Fatalf("Disconnected() returned error: %v", err)
	}

	if err := ctx.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
}

// TestContextCloseForceDisconnectsOpenConnections verifies Close forcibly
// disconnects any connections created from it that are still open, rather
// than refusing to run. rc_free requires every connection be freed
// beforehand, and using a connection that outlived its context aborts the
// process, so Close must not leave that step to the caller.
func TestContextCloseForceDisconnectsOpenConnections(t *testing.T) {
	ctx, err := Init()
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}

	connected, err := ctx.NewConnection()
	if err != nil {
		t.Fatalf("NewConnection() returned error: %v", err)
	}
	if err := connected.Connected(); err != nil {
		t.Fatalf("Connected() returned error: %v", err)
	}

	// A connection on which Connected was never called should also be
	// force-disconnected cleanly.
	unconnected, err := ctx.NewConnection()
	if err != nil {
		t.Fatalf("NewConnection() returned error: %v", err)
	}

	if err := ctx.Close(); err != nil {
		t.Fatalf("Close() with open connections returned error: %v", err)
	}

	if err := connected.Close(); !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("Disconnected() on force-closed connection = %v, want ErrConnectionClosed", err)
	}
	if err := unconnected.Close(); !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("Disconnected() on force-closed connection = %v, want ErrConnectionClosed", err)
	}
}

// TestConnectionDisconnectedWithoutConnected verifies that calling Close on a
// Connection that Connected was never called on succeeds without crashing,
// while still freeing the connection's resources.
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

	if err := conn.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}

	if err := conn.Close(); !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("second Close() = %v, want ErrConnectionClosed", err)
	}
}
