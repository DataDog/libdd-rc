package rcx509

import (
	"context"
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
		url:     "ws://example.com",
		dialer:  &fakeWebsocketDialer{dialErr: errors.New("no backend available")},
		ffiCtx:  ffi,
		backoff: newBackoff(defaultInitialBackoff, defaultMaxBackoff, defaultBackoffMultiplier),
		sleep:   sleepCtx,
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
	// guarantees is that Start() cannot be left running forever, even while
	// waiting out a backoff delay.
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
		url:     "ws://example.com",
		dialer:  &fakeWebsocketDialer{dialErr: errors.New("no backend available")},
		ffiCtx:  ffi,
		backoff: newBackoff(defaultInitialBackoff, defaultMaxBackoff, defaultBackoffMultiplier),
		sleep:   sleepCtx,
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

// TestRunBacksOffWithNonDecreasingDelaysOnRepeatedFailures confirms that
// run() consults its backoff between failed connection attempts, and that
// the delays it waits out don't shrink across immediate, repeated failures.
func TestRunBacksOffWithNonDecreasingDelaysOnRepeatedFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	const wantAttempts = 4
	var delays []time.Duration

	client := &Client{
		url:     "ws://example.com",
		dialer:  &fakeWebsocketDialer{dialErr: errors.New("no backend available")},
		ffiCtx:  &fakeFFIContext{conn: newFakeFFIConnection()},
		backoff: newBackoff(10*time.Millisecond, time.Second, defaultBackoffMultiplier),
		sleep: func(_ context.Context, d time.Duration) bool {
			delays = append(delays, d)
			if len(delays) >= wantAttempts {
				cancel()
				return false
			}
			return true
		},
	}

	client.run(ctx)

	if len(delays) != wantAttempts {
		t.Fatalf("got %d backoff delays, want %d", len(delays), wantAttempts)
	}
	for i := 1; i < len(delays); i++ {
		if delays[i] < delays[i-1] {
			t.Fatalf("delay[%d] = %v is less than delay[%d] = %v; want non-decreasing", i, delays[i], i-1, delays[i-1])
		}
	}
}

// TestRunDoesNotResetBackoffOnSlowFailedDial confirms that a dial which takes
// longer than resetThreshold to fail is still treated as a failed connection
// attempt, not a healthy session: the backoff must not be reset, since the
// clock for resetThreshold only starts once a connection is established.
func TestRunDoesNotResetBackoffOnSlowFailedDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	const wantAttempts = 2
	var delays []time.Duration

	client := &Client{
		url:     "ws://example.com",
		dialer:  &fakeWebsocketDialer{dialErr: errors.New("no backend available"), dialDelay: resetThreshold + 10*time.Millisecond},
		ffiCtx:  &fakeFFIContext{conn: newFakeFFIConnection()},
		backoff: newBackoff(10*time.Millisecond, time.Second, defaultBackoffMultiplier),
		sleep: func(_ context.Context, d time.Duration) bool {
			delays = append(delays, d)
			if len(delays) >= wantAttempts {
				cancel()
				return false
			}
			return true
		},
	}

	client.run(ctx)

	if len(delays) != wantAttempts {
		t.Fatalf("got %d backoff delays, want %d", len(delays), wantAttempts)
	}
	if delays[1] < delays[0] {
		t.Fatalf("delay[1] = %v is less than delay[0] = %v; a slow failed dial must not reset the backoff", delays[1], delays[0])
	}
}

// TestShouldResetBackoffAtThreshold checks the boundary of the invariant
// that a session must persist for the reset threshold before its failure
// stops being held against the next reconnection attempt.
func TestShouldResetBackoffAtThreshold(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     bool
	}{
		{name: "well under threshold", duration: 1 * time.Second, want: false},
		{name: "just under threshold", duration: resetThreshold - time.Millisecond, want: false},
		{name: "exactly at threshold", duration: resetThreshold, want: true},
		{name: "well over threshold", duration: resetThreshold + time.Second, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldResetBackoff(tt.duration); got != tt.want {
				t.Errorf("shouldResetBackoff(%v) = %v, want %v", tt.duration, got, tt.want)
			}
		})
	}
}
