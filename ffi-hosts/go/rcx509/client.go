// Package rcx509 is the public Go API for libdd-rc. It wraps the internal
// FFI bindings in internal/libddrcffi, and will grow to include the
// networking layer that drives them.
package rcx509

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sync"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi"
	magictunnelv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel"
)

// ErrAlreadyStarted is returned by Start when called more than once on the
// same Client.
var ErrAlreadyStarted = errors.New("rcx509: client already started")

// ErrClientClosed is returned by Start when called on a Client that has
// already been closed.
var ErrClientClosed = errors.New("rcx509: client is closed")

// Client manages a connection between the RC x509 backend and the local
// rc-x509-client subsystem.
//
// Once started, it self-manages a WebSocket connection, reconnecting as
// needed, and driving I/O between the RC backend and the rc-x509-client
// layer.
type Client struct {
	ffiCtx FFIContext

	url string

	// Allows for better unit testing
	dialer WebsocketDialer

	wg sync.WaitGroup

	mu      sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
}

// NewClient initializes a new Client backed by its own instance of the
// rc-x509-client subsystem. The connection is not started until explicited
// requested by the user.
//
// The url must be a ws:// or wss:// URL for a websocket connection.
func NewClient(rawURL string) (*Client, error) {
	if err := validateURL(rawURL); err != nil {
		return nil, err
	}

	ctx, err := libddrcffi.Init()
	if err != nil {
		return nil, err
	}
	return &Client{ffiCtx: &ffiContext{ctx}, url: rawURL, dialer: &CoderWebsocketDialer{}}, nil
}

// Start begins the Client's background connection loop: it continuously
// attempts to establish a WebSocket connection to url, driving the FFI
// layer's connection lifecycle accordingly, reconnecting whenever
// the connection is lost or cannot be established.
//
// Start() blocks, returning only when the client will no longer be attempting
// to run it's ongoing session maintenance loop. The caller is responsible for
// the appropriate concurrency management. Once a client has exited, it must be
// created again.
//
// Start() may only be called once, calling start a second time returns an error.
func (c *Client) Start() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClientClosed
	}
	if c.started {
		c.mu.Unlock()
		return ErrAlreadyStarted
	}
	c.started = true

	// Create a context that will allow us to stop the background
	// goroutine on a Close() call. cancel and wg.Add are set up here, still
	// under c.mu, so that a concurrent Close() can never observe c.started
	// without also observing a usable c.cancel and a non-zero wg count.
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.wg.Add(1)
	c.mu.Unlock()

	defer c.wg.Done()
	c.run(ctx)

	return nil
}

// Close sends a signal to the management loop to shutdown operations, waits
// for the system to terminate, and releases the FFI context.
//
// Close is safe to call whether or not Start was ever called, as the FFI context
// still needs to be cleaned up even if Start() was never invoked.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClientClosed
	}
	c.closed = true
	cancel := c.cancel
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	// Wait for done
	c.wg.Wait()

	if err := c.ffiCtx.Close(); err != nil {
		return fmt.Errorf("rcx509: failed to shut down client: %w", err)
	}

	return nil
}

// RegisterHandler registers the provided function to be called when dispatch messages matching
// the given namespace are processed by the backend.
func (c *Client) RegisterHandler(namespace magictunnelv1.Namespace, fn libddrcffi.HandlerFunc) error {
	return libddrcffi.RegisterHandler(namespace, fn)
}

// run is the Client's background connection loop, started by Start.
//
// run will seek to maintain a session with the RC backend, handling
// the connection lifecycle each time a new one needs to be established. It
// will only stop when the provided context signals the run loop should terminate
// either via an error or a done signal.
func (c *Client) run(ctx context.Context) {
	for {
		err := c.runSession(ctx)
		if err != nil {
			log.Printf("session closed: %v", err)
		}

		// Err handles both errors, and the context being canceled.
		if ctx.Err() != nil {
			log.Printf("closing run because of context err: %v", ctx.Err())
			return
		}
	}
}

// validateURL reports an error if rawURL is not a ws:// or wss:// URL with a
// non-empty host.
func validateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("rcx509: invalid url: %w", err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return fmt.Errorf("rcx509: url scheme must be ws or wss, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("rcx509: url must have a non-empty host")
	}
	return nil
}
