// Package rcx509 is the public Go API for libdd-rc. It wraps the internal
// FFI bindings in internal/libddrcffi, and will grow to include the
// networking layer that drives them.
package rcx509

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi"
)

// ErrAlreadyStarted is returned by Start when called more than once on the
// same Client.
var ErrAlreadyStarted = errors.New("rcx509: client already started")

// ErrClientClosed is returned by Start when called on a Client that has
// already been closed.
var ErrClientClosed = errors.New("rcx509: client is closed")

// HandlerFunc handles a request for one service URI (a fully-qualified gRPC
// method name) and returns the response payload. Handlers run on an
// rcx509-owned goroutine, and MUST NOT take more than 30s to execute (else ctx
// is cancelled, and the RPC endpoint is marked unhealthy and subject to rate
// limiting).
//
// If the returned err error is non-nil, the RPC endpoint MAY be marked as
// unhealthy and rate limited, affecting future delivery.
type HandlerFunc = libddrcffi.HandlerFunc

// Client manages a connection between the RC x509 backend and the local
// rc-x509-client subsystem.
//
// Once started, it self-manages a WebSocket connection, reconnecting as
// needed, and driving I/O between the RC backend and the rc-x509-client
// layer.
type Client struct {
	ffiCtx FFIContext

	url string

	// endpointHostname is the DNS address of the Datadog DC reported to the
	// FFI layer for each connection it establishes, used to verify the
	// signatures of the messages received over that connection.
	endpointHostname string

	// Allows for better unit testing
	dialer WebsocketDialer

	// backoff tracks the delay before the next reconnection attempt. It is
	// only ever touched from the run loop, so it needs no locking.
	backoff *backoff

	// sleep waits out a reconnection delay, returning false if ctx is
	// canceled first. Allows for better unit testing.
	sleep func(ctx context.Context, d time.Duration) bool

	wg sync.WaitGroup

	mu      sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
}

type options struct {
	apiKey     string
	httpClient *http.Client

	// The "endpoint" (DNS hostname) being connected to.
	//
	// This is required to match SAN entries in the certificate chain during
	// signature validation, and should be set to the DC the client is connected
	// to.
	endpoint string
}

// Option configures optional Client behaviour.
type Option func(*options)

// WithAPIKey sends key in the DD-API-KEY HTTP header when dialing the
// backend. An empty key sends no header.
func WithAPIKey(key string) Option {
	return func(o *options) { o.apiKey = key }
}

// WithHTTPClient uses client for WebSocket connection attempts. This allows
// users to optionally supply an HTTP client with custom proxy, TLS, dialer,
// or timeout configurations. A non-zero client timeout bounds the WebSocket
// handshake, not the lifetime of the established connection.
func WithHTTPClient(client *http.Client) Option {
	return func(o *options) { o.httpClient = client }
}

// WithDCHostname sets the DNS address used when verifying signatures from the
// Datadog DC that issued them (e.g. config.datadoghq.com).
//
// If this value does not match the DNS address of the Datadog DC that signed a
// message, a verification error will occur.
//
// By default, this value is extracted from the URL passed to NewClient, but in
// cases where this may differ from the DC address (i.e. when dialling to an
// non-transparent proxy) this option allows the verification hostname to be
// changed.
func WithDCHostname(endpoint string) Option {
	return func(o *options) { o.endpoint = endpoint }
}

// NewClient initializes a new Client backed by its own instance of the
// rc-x509-client subsystem. The connection is not started until explicited
// requested by the user.
//
// The url must be a ws:// or wss:// URL for a websocket connection.
//
// appName and version identify the host application, and are reported to the
// backend as part of the connection handshake.
func NewClient(rawURL, appName, version string, opts ...Option) (*Client, error) {
	u, err := parseURL(rawURL)
	if err != nil {
		return nil, err
	}

	var cfg options
	cfg.endpoint = u.Hostname()

	for _, opt := range opts {
		opt(&cfg)
	}

	ctx, err := libddrcffi.Init(appName, version)
	if err != nil {
		return nil, err
	}
	return &Client{
		ffiCtx:           &ffiContext{ctx},
		url:              rawURL,
		endpointHostname: cfg.endpoint,
		dialer:           &CoderWebsocketDialer{APIKey: cfg.apiKey, HTTPClient: cfg.httpClient},
		backoff:          newBackoff(defaultInitialBackoff, defaultMaxBackoff, defaultBackoffMultiplier),
		sleep:            sleepCtx,
	}, nil
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

// RegisterHandler registers the provided function to be called when dispatch
// messages matching the given uri (the fully-qualified gRPC method name) are
// processed by the backend.
func (c *Client) RegisterHandler(uri string, fn HandlerFunc) error {
	return libddrcffi.RegisterHandler(uri, fn)
}

// run is the Client's background connection loop, started by Start.
//
// run will seek to maintain a session with the RC backend, handling
// the connection lifecycle each time a new one needs to be established. It
// will only stop when the provided context signals the run loop should terminate
// either via an error or a done signal.
//
// Reconnection attempts are spaced out with an exponential backoff, so a
// persistently unreachable backend isn't hammered in a tight loop. A session
// that stays up for at least resetThreshold is treated as healthy enough
// that its eventual failure shouldn't be held against the next reconnection
// attempt, so the backoff is reset before it is next consulted.
//
// Connection establishment happens here rather than inside runSession so
// that the clock used for that resetThreshold comparison only starts once a
// connection has actually been established: a dial that takes a while before
// failing must not be mistaken for a healthy session.
func (c *Client) run(ctx context.Context) {
	for {
		conn, ws, err := c.establishConnection(ctx)
		if err != nil {
			log.Printf("failed to establish connection: %v", err)

			if ctx.Err() != nil {
				log.Printf("closing run because of context err: %v", ctx.Err())
				return
			}

			if !c.sleep(ctx, c.backoff.Next()) {
				return
			}
			continue
		}

		start := time.Now()
		err = c.runSession(ctx, conn, ws)
		if err != nil {
			log.Printf("session closed: %v", err)
		}

		// Err handles both errors, and the context being canceled.
		if ctx.Err() != nil {
			log.Printf("closing run because of context err: %v", ctx.Err())
			return
		}

		if shouldResetBackoff(time.Since(start)) {
			c.backoff.Reset()
		}

		if !c.sleep(ctx, c.backoff.Next()) {
			return
		}
	}
}

// parseURL parses rawURL, returning an error if it is not a ws:// or wss://
// URL with a non-empty host.
func parseURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("rcx509: invalid url: %w", err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, fmt.Errorf("rcx509: url scheme must be ws or wss, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("rcx509: url must have a non-empty host")
	}
	return u, nil
}

// shouldResetBackoff reports whether a session that stayed up for
// sessionDuration was long-lived enough that its eventual failure shouldn't
// be held against the next reconnection attempt's backoff delay.
func shouldResetBackoff(sessionDuration time.Duration) bool {
	return sessionDuration >= resetThreshold
}

// sleepCtx waits for d to elapse, returning true, or for ctx to be canceled,
// returning false. A non-positive d returns true immediately.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}

	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
