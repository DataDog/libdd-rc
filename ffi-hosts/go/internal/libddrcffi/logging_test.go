package libddrcffi

import (
	"testing"
	"time"
)

type logEvent struct {
	level           LogLevel
	target, message string
}

// TestSetLogHandler exercises the full FFI log bridge end to end: it
// registers a handler, drives connection lifecycle events that emit log
// messages on the Rust side, and verifies they arrive with fully marshalled
// Go values. It also verifies a second registration attempt within the same
// process is rejected, since the underlying subscriber cannot be replaced.
func TestSetLogHandler(t *testing.T) {
	// Buffered and drained via a non-blocking send: the handler contract
	// forbids blocking, and the client library logs from the same runtime
	// thread that a later Close() must join, so a handler that blocks once
	// the channel fills up deadlocks the whole test.
	events := make(chan logEvent, 16)

	if err := SetLogHandler(func(level LogLevel, target, message string) {
		select {
		case events <- logEvent{level, target, message}:
		default:
		}
	}, LogLevelDebug); err != nil {
		t.Fatalf("SetLogHandler() returned error: %v", err)
	}

	ctx, err := Init()
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}
	defer ctx.Close()

	conn, err := ctx.NewConnection()
	if err != nil {
		t.Fatalf("NewConnection() returned error: %v", err)
	}
	defer conn.Close()

	if err := conn.Connected(); err != nil {
		t.Fatalf("Connected() returned error: %v", err)
	}

	select {
	case e := <-events:
		if e.target == "" {
			t.Error("got event with empty target, want a non-empty target")
		}
		if e.message == "" {
			t.Error("got event with empty message, want a non-empty message")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a log event from the connection I/O task")
	}

	if err := SetLogHandler(func(LogLevel, string, string) {}, LogLevelDebug); err != ErrLogHandlerAlreadySet {
		t.Fatalf("second SetLogHandler() = %v, want ErrLogHandlerAlreadySet", err)
	}
}
