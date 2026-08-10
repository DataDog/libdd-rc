package ddrc

import (
	"errors"
	"sync"

	magictunnelv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel"
)

// HandlerFunc processes a dispatched MagicTunnelRequest payload for a single
// namespace and returns the response payload to be sent back via
// rc_conn_dispatch_result. Both payload and response are the namespace's own
// wire format (e.g. a further protobuf-encoded oneof by subtopic); ddrc does
// not decode past the namespace boundary.
//
// A handler runs on the invoke worker goroutine of the Connection that
// received the payload, and must not call back into that Connection:
// Connection.Disconnected waits for in-flight handlers to return while
// holding the connection lock, so a handler calling Recv or Disconnected
// deadlocks. A handler that returns an error, or panics, has that reported to
// the client library as a handler error.
type HandlerFunc func(correlationID uint64, payload []byte) (response []byte, err error)

// ErrHandlerExists is returned by RegisterHandler when a handler is already
// registered for the given namespace.
var ErrHandlerExists = errors.New("ddrc: handler already registered for namespace")

// ErrHandlerNotFound is returned by UnregisterHandler when no handler is
// registered for the given namespace.
var ErrHandlerNotFound = errors.New("ddrc: no handler registered for namespace")

// dispatcher routes dispatched MagicTunnelRequest payloads to registered
// handlers by namespace.
//
// There is exactly one dispatcher per process, shared by all connections.
type dispatcher struct {
	mu       sync.RWMutex
	handlers map[magictunnelv1.Namespace]HandlerFunc
}

var globalDispatcher = &dispatcher{handlers: make(map[magictunnelv1.Namespace]HandlerFunc)}

func (d *dispatcher) register(ns magictunnelv1.Namespace, h HandlerFunc) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.handlers[ns]; exists {
		return ErrHandlerExists
	}
	d.handlers[ns] = h
	return nil
}

func (d *dispatcher) unregister(ns magictunnelv1.Namespace) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.handlers[ns]; !exists {
		return ErrHandlerNotFound
	}
	delete(d.handlers, ns)
	return nil
}

func (d *dispatcher) lookup(ns magictunnelv1.Namespace) (HandlerFunc, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	h, ok := d.handlers[ns]
	return h, ok
}

// RegisterHandler registers h to process dispatched MagicTunnelRequest
// payloads for ns. Handlers may be registered at any time, including after
// connections are already active. Registering a namespace that already has a
// handler returns ErrHandlerExists.
func RegisterHandler(ns magictunnelv1.Namespace, h HandlerFunc) error {
	return globalDispatcher.register(ns, h)
}

// UnregisterHandler removes the handler registered for ns. Unregistering a
// namespace with no registered handler returns ErrHandlerNotFound.
func UnregisterHandler(ns magictunnelv1.Namespace) error {
	return globalDispatcher.unregister(ns)
}
