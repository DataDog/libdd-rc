package libddrcffi

import (
	"errors"
	"sync"
	"testing"

	magictunnelv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel"
)

func noopHandler(correlationID uint64, payload []byte) ([]byte, error) {
	return nil, nil
}

func TestRegisterHandler_Success(t *testing.T) {
	const ns = magictunnelv1.Namespace_NAMESPACE_REMOTE_CONFIG
	defer func() { _ = UnregisterHandler(ns) }()

	if err := RegisterHandler(ns, noopHandler); err != nil {
		t.Fatalf("RegisterHandler() returned error: %v", err)
	}
}

func TestRegisterHandler_DuplicateReturnsError(t *testing.T) {
	const ns = magictunnelv1.Namespace_NAMESPACE_REMOTE_CONFIG
	defer func() { _ = UnregisterHandler(ns) }()

	if err := RegisterHandler(ns, noopHandler); err != nil {
		t.Fatalf("first RegisterHandler() returned error: %v", err)
	}

	called := false
	replacement := func(correlationID uint64, payload []byte) ([]byte, error) {
		called = true
		return nil, nil
	}

	err := RegisterHandler(ns, replacement)
	if !errors.Is(err, ErrHandlerExists) {
		t.Fatalf("second RegisterHandler() = %v, want ErrHandlerExists", err)
	}

	h, ok := globalDispatcher.lookup(ns)
	if !ok {
		t.Fatal("expected original handler to remain registered")
	}
	if _, _ = h(0, nil); called {
		t.Fatal("duplicate registration overwrote the original handler")
	}
}

func TestUnregisterHandler_Success(t *testing.T) {
	const ns = magictunnelv1.Namespace_NAMESPACE_REMOTE_CONFIG

	if err := RegisterHandler(ns, noopHandler); err != nil {
		t.Fatalf("RegisterHandler() returned error: %v", err)
	}
	if err := UnregisterHandler(ns); err != nil {
		t.Fatalf("UnregisterHandler() returned error: %v", err)
	}

	// Re-registering after unregistering must succeed.
	if err := RegisterHandler(ns, noopHandler); err != nil {
		t.Fatalf("RegisterHandler() after unregister returned error: %v", err)
	}
	defer func() { _ = UnregisterHandler(ns) }()
}

func TestUnregisterHandler_MissingReturnsError(t *testing.T) {
	const ns = magictunnelv1.Namespace_NAMESPACE_UNSPECIFIED

	if err := UnregisterHandler(ns); !errors.Is(err, ErrHandlerNotFound) {
		t.Fatalf("UnregisterHandler() = %v, want ErrHandlerNotFound", err)
	}
}

func TestDispatcher_ConcurrentRegisterAndLookup(t *testing.T) {
	const workers = 16

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ns := magictunnelv1.Namespace(i)

			if err := RegisterHandler(ns, noopHandler); err != nil {
				t.Errorf("RegisterHandler(%v) returned error: %v", ns, err)
				return
			}
			if _, ok := globalDispatcher.lookup(ns); !ok {
				t.Errorf("lookup(%v) did not find registered handler", ns)
			}
			if err := UnregisterHandler(ns); err != nil {
				t.Errorf("UnregisterHandler(%v) returned error: %v", ns, err)
			}
		}(i)
	}
	wg.Wait()
}
