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

	"github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi"
)

// ErrAlreadyStarted is returned by Start when called more than once on the
// same Client.
var ErrAlreadyStarted = errors.New("rcx509: client already started")

// ErrClientClosed is returned by Start when called on a Client that has
// already been closed.
var ErrClientClosed = errors.New("rcx509: client is closed")

// Client manages a connection between the RC x509 backend and the local x509
// library.
//
// Once started, it self-manages a WebSocket connection to url, reconnecting as
// needed, and drives the FFI layer's connection and message processing lifecycle.
type Client struct {
	ffiCtx *libddrcffi.X509Context

	url string

	// Allows for better unit testing
	dialer WebsocketDialer

	started bool
	closed  bool
	cancel  context.CancelFunc
}

// NewClient initializes a new Client backed by its own instance of the
// rc-x509-client subsystem, which will connect to the RC backend at url once
// Start is called. url must be a ws:// or wss:// URL.
//
// NewClient does not itself attempt any connection.
func NewClient(rawURL string) (*Client, error) {
	if err := validateURL(rawURL); err != nil {
		return nil, err
	}

	ctx, err := libddrcffi.Init()
	if err != nil {
		return nil, err
	}
	return &Client{ffiCtx: ctx, url: rawURL, dialer: &CoderWebsocketDialer{}}, nil
}

// Start begins the Client's background connection loop: it continuously
// attempts to establish a WebSocket connection to url, driving the FFI
// layer's connection lifecycle accordingly, reconnecting whenever
// the connection is lost or cannot be established.
//
// Start returns immediately once the loop has been started; it does not
// wait for a connection to be established. It is an error to call Start more
// than once, or after Close.
func (c *Client) Start() error {
	if c.closed {
		return ErrClientClosed
	}
	if c.started {
		return ErrAlreadyStarted
	}
	c.started = true

	// Create a context that will allow us to stop the background
	// goroutine on a Close() call.
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel

	go c.run(ctx)

	return nil
}

// Close shuts down the Client's rc-x509-client subsystem, force-disconnecting
// any connections that have not already been released. If Start has been
// called, Close first stops the background connection loop and waits for it
// to exit, so no Connection created by the loop outlives the underlying
// context.
//
// Close blocks until the FFI layer has finished dispatching any in-flight
// messages, which means it waits on caller-supplied handlers; a handler that
// never returns will hang Close.
//
// Calling Close more than once returns ErrClientClosed. A Close that fails
// partway through cannot be retried: the underlying context is single-shot
// and is already spent by then.
func (c *Client) Close() error {
	if c.closed {
		return ErrClientClosed
	}
	c.closed = true

	cancel := c.cancel
	if cancel != nil {
		cancel()
	}

	// ??? Should we actually try to wait for runSession to complete here?

	if err := c.ffiCtx.Close(); err != nil {
		return fmt.Errorf("rcx509: failed to shut down client: %w", err)
	}
	return nil
}

// run is the Client's background connection loop, started by Start.
//
// run will seek to always maintain a session with the RC backend, handling
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
