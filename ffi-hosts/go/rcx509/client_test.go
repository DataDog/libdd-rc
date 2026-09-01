package rcx509

import (
	"errors"
	"testing"
	"time"
)

// TestValidateURLAcceptsValidURLs is the happy path test for URLs passed
// to NewClient.
func TestValidateURLAcceptsValidURLs(t *testing.T) {
	urls := []string{
		"ws://example.com",
		"wss://example.com",
		"wss://example.com:443/path",
	}

	for _, u := range urls {
		if err := validateURL(u); err != nil {
			t.Errorf("validateURL(%q) returned unexpected error: %v", u, err)
		}
	}
}

// TestValidateURLRejectsInvalidURLs is a sanity check on the URL
// validation function.
func TestValidateURLRejectsInvalidURLs(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "invalid scheme (http)", url: "http://example.com"},
		{name: "invalid scheme (https)", url: "https://example.com"},
		{name: "missing host", url: "ws:///path"},
		{name: "malformed url", url: "://not-a-url"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateURL(tt.url); err == nil {
				t.Errorf("validateURL(%q) expected an error, got nil", tt.url)
			}
		})
	}
}

// TestStartCloseConcurrentDoesNotOrphanRunLoop exercises the race between
// Start and a concurrent Close, should the caller decide to do something
// "interesting". If this is not properly guarded, it's possible we leak
// the run loop and/or fail to clean up resources.
func TestStartCloseConcurrentDoesNotOrphanRunLoop(t *testing.T) {
	ffi := &fakeFFIContext{conn: newFakeFFIConnection()}
	client := &Client{
		url:    "ws://example.com",
		dialer: &fakeWebsocketDialer{dialErr: errors.New("no backend available")},
		ffiCtx: ffi,
	}

	started := make(chan error, 1)
	go func() {
		started <- client.Start()
	}()

	if err := client.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}

	// Start() may either have run and been stopped by Close() (nil), or
	// Close() may have completed before Start() even got going
	// (ErrClientClosed) -- both are legitimate interleavings. What Close()
	// guarantees is that Start() cannot be left running forever.
	select {
	case err := <-started:
		if err != nil && !errors.Is(err, ErrClientClosed) {
			t.Fatalf("Start() returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start() did not return after Close(); run loop appears orphaned")
	}

	if ffi.closeCalls != 1 {
		t.Fatalf("ffiCtx.Close() called %d times, want 1", ffi.closeCalls)
	}
}

// TestCloseBeforeStartPreventsSubsequentStart confirms Close is safe to call
// on a Client that was never started, and that it stops Start from running
// afterward.
func TestCloseBeforeStartPreventsSubsequentStart(t *testing.T) {
	client := &Client{
		url:    "ws://example.com",
		dialer: &fakeWebsocketDialer{},
		ffiCtx: &fakeFFIContext{},
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}

	if err := client.Start(); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("Start() after Close() = %v, want ErrClientClosed", err)
	}
}

// TestCloseFreesFFIContextWithoutStart ensures Close releases the FFI
// context even when Start was never called so that the FFI is not leaked.
func TestCloseFreesFFIContextWithoutStart(t *testing.T) {
	ffi := &fakeFFIContext{}
	client := &Client{
		url:    "ws://example.com",
		dialer: &fakeWebsocketDialer{},
		ffiCtx: ffi,
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}

	if ffi.closeCalls != 1 {
		t.Fatalf("ffiCtx.Close() called %d times, want 1", ffi.closeCalls)
	}
}

// TestCloseFreesFFIContextExactlyOnceAfterStart validates that after a
// Start/Close cycle, the FFI context is freed exactly once.
func TestCloseFreesFFIContextExactlyOnceAfterStart(t *testing.T) {
	ffi := &fakeFFIContext{}
	client := &Client{
		url:    "ws://example.com",
		dialer: &fakeWebsocketDialer{dialErr: errors.New("no backend available")},
		ffiCtx: ffi,
	}

	started := make(chan error, 1)
	go func() {
		started <- client.Start()
	}()

	if err := client.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}

	select {
	case err := <-started:
		if err != nil && !errors.Is(err, ErrClientClosed) {
			t.Fatalf("Start() returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start() did not return after Close()")
	}

	if ffi.closeCalls != 1 {
		t.Fatalf("ffiCtx.Close() called %d times, want 1", ffi.closeCalls)
	}

	if err := client.Close(); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("second Close() = %v, want ErrClientClosed", err)
	}
	if ffi.closeCalls != 1 {
		t.Fatalf("ffiCtx.Close() called %d times after second Close(), want 1", ffi.closeCalls)
	}
}
