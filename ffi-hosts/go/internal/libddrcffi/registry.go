package libddrcffi

import (
	"errors"
	"sync"
)

// HandlerFunc processes a request for a single service URI (e.g.
// `rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping`) and returns the
// response payload to be sent back.
//
// The handler is responsible for deserialising the protobuf payload to the
// appropriate type for the RPC method, and serialising the appropriate response
// type that is returned to the backend.
//
// A handler MUST NOT call into the underlying RC client library.
//
// A handler that returns an error, or panics, has that reported to the client
// library as a handler error. Prefer returning a structured error response
// instead of a unstructured `err`.
type HandlerFunc func(correlationID uint64, payload []byte) (response []byte, err error)

// ErrHandlerExists is returned by RegisterHandler when a handler is already
// registered for the given URI.
var ErrHandlerExists = errors.New("ddrc: handler already registered for uri")

// ErrHandlerNotFound is returned by UnregisterHandler when no handler is
// registered for the given URI.
var ErrHandlerNotFound = errors.New("ddrc: no handler registered for uri")

// handlerRegistry stores a mapping of `HandlerFunc` to the request `uri` that the
// `HandlerFunc` is responsible for.
//
// There is exactly one handlerRegistry per process, shared by all connections.
type handlerRegistry struct {
	mu       sync.RWMutex
	handlers map[string]HandlerFunc
}

var globalHandlerRegistry = &handlerRegistry{handlers: make(map[string]HandlerFunc)}

func (d *handlerRegistry) register(uri string, h HandlerFunc) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.handlers[uri]; exists {
		return ErrHandlerExists
	}
	d.handlers[uri] = h
	return nil
}

func (d *handlerRegistry) unregister(uri string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.handlers[uri]; !exists {
		return ErrHandlerNotFound
	}
	delete(d.handlers, uri)
	return nil
}

func (d *handlerRegistry) lookup(uri string) (HandlerFunc, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	h, ok := d.handlers[uri]
	return h, ok
}

// RegisterHandler registers h to process dispatched MagicTunnelRequest payloads
// for uri, the fully-qualified gRPC method name (e.g.
// "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping").
//
// Handlers may be registered at any time, including after connections are
// already active (but this risks missing messages). Registering a uri that
// already has a handler returns ErrHandlerExists.
func RegisterHandler(uri string, h HandlerFunc) error {
	return globalHandlerRegistry.register(uri, h)
}

// UnregisterHandler removes the handler registered for uri. Unregistering a
// uri with no registered handler returns ErrHandlerNotFound.
func UnregisterHandler(uri string) error {
	return globalHandlerRegistry.unregister(uri)
}
