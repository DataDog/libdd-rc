package libddrcffi

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func noopHandler(ctx context.Context, correlationID uint64, payload []byte) ([]byte, error) {
	return nil, nil
}

func TestRegisterHandler_Success(t *testing.T) {
	const uri = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"
	defer func() { _ = UnregisterHandler(uri) }()

	if err := RegisterHandler(uri, noopHandler); err != nil {
		t.Fatalf("RegisterHandler() returned error: %v", err)
	}
}

func TestRegisterHandler_DuplicateReturnsError(t *testing.T) {
	const uri = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"
	defer func() { _ = UnregisterHandler(uri) }()

	if err := RegisterHandler(uri, noopHandler); err != nil {
		t.Fatalf("first RegisterHandler() returned error: %v", err)
	}

	called := false
	replacement := func(ctx context.Context, correlationID uint64, payload []byte) ([]byte, error) {
		called = true
		return nil, nil
	}

	err := RegisterHandler(uri, replacement)
	if !errors.Is(err, ErrHandlerExists) {
		t.Fatalf("second RegisterHandler() = %v, want ErrHandlerExists", err)
	}

	h, ok := globalHandlerRegistry.lookup(uri)
	if !ok {
		t.Fatal("expected original handler to remain registered")
	}
	if _, _ = h(context.Background(), 0, nil); called {
		t.Fatal("duplicate registration overwrote the original handler")
	}
}

func TestUnregisterHandler_Success(t *testing.T) {
	const uri = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"

	if err := RegisterHandler(uri, noopHandler); err != nil {
		t.Fatalf("RegisterHandler() returned error: %v", err)
	}
	if err := UnregisterHandler(uri); err != nil {
		t.Fatalf("UnregisterHandler() returned error: %v", err)
	}

	// Re-registering after unregistering must succeed.
	if err := RegisterHandler(uri, noopHandler); err != nil {
		t.Fatalf("RegisterHandler() after unregister returned error: %v", err)
	}
	defer func() { _ = UnregisterHandler(uri) }()
}

func TestUnregisterHandler_MissingReturnsError(t *testing.T) {
	const uri = "rc.x509.magic_tunnel.remote_config.v1.DebugService/DoesNotExist"

	if err := UnregisterHandler(uri); !errors.Is(err, ErrHandlerNotFound) {
		t.Fatalf("UnregisterHandler() = %v, want ErrHandlerNotFound", err)
	}
}

func TestHandlerRegistry_ConcurrentRegisterAndLookup(t *testing.T) {
	const workers = 16

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			uri := fmt.Sprintf("rc.x509.magic_tunnel.remote_config.v1.DebugService/Worker%d", i)

			if err := RegisterHandler(uri, noopHandler); err != nil {
				t.Errorf("RegisterHandler(%v) returned error: %v", uri, err)
				return
			}
			if _, ok := globalHandlerRegistry.lookup(uri); !ok {
				t.Errorf("lookup(%v) did not find registered handler", uri)
			}
			if err := UnregisterHandler(uri); err != nil {
				t.Errorf("UnregisterHandler(%v) returned error: %v", uri, err)
			}
		}(i)
	}
	wg.Wait()
}
