package libddrcffi

import (
	"errors"
	"testing"
)

func TestConnLifecycleMarkConnected(t *testing.T) {
	t.Run("succeeds from the initial state", func(t *testing.T) {
		var l connLifecycle
		if err := l.markConnected(); err != nil {
			t.Fatalf("markConnected() = %v, want nil", err)
		}
		if !l.connected {
			t.Fatal("markConnected() left connected = false")
		}
	})

	t.Run("rejects a second call", func(t *testing.T) {
		var l connLifecycle
		if err := l.markConnected(); err != nil {
			t.Fatalf("first markConnected() = %v, want nil", err)
		}
		if err := l.markConnected(); !errors.Is(err, ErrConnectionAlreadyConnected) {
			t.Fatalf("second markConnected() = %v, want ErrConnectionAlreadyConnected", err)
		}
	})

	t.Run("rejects a closed connection", func(t *testing.T) {
		var l connLifecycle
		if _, err := l.markClosed(); err != nil {
			t.Fatalf("markClosed() = %v, want nil", err)
		}
		if err := l.markConnected(); !errors.Is(err, ErrConnectionClosed) {
			t.Fatalf("markConnected() after markClosed() = %v, want ErrConnectionClosed", err)
		}
	})
}

func TestConnLifecycleMarkClosed(t *testing.T) {
	t.Run("reports wasConnected false when never connected", func(t *testing.T) {
		var l connLifecycle
		wasConnected, err := l.markClosed()
		if err != nil {
			t.Fatalf("markClosed() = %v, want nil", err)
		}
		if wasConnected {
			t.Fatal("markClosed() wasConnected = true, want false")
		}
	})

	t.Run("reports wasConnected true when previously connected", func(t *testing.T) {
		var l connLifecycle
		if err := l.markConnected(); err != nil {
			t.Fatalf("markConnected() = %v, want nil", err)
		}
		wasConnected, err := l.markClosed()
		if err != nil {
			t.Fatalf("markClosed() = %v, want nil", err)
		}
		if !wasConnected {
			t.Fatal("markClosed() wasConnected = false, want true")
		}
	})

	t.Run("rejects a second call", func(t *testing.T) {
		var l connLifecycle
		if _, err := l.markClosed(); err != nil {
			t.Fatalf("first markClosed() = %v, want nil", err)
		}
		if _, err := l.markClosed(); !errors.Is(err, ErrConnectionClosed) {
			t.Fatalf("second markClosed() = %v, want ErrConnectionClosed", err)
		}
	})
}

func TestConnLifecycleCheckRecvable(t *testing.T) {
	t.Run("rejects before Connected", func(t *testing.T) {
		var l connLifecycle
		if err := l.checkRecvable(); !errors.Is(err, ErrConnectionNotConnected) {
			t.Fatalf("checkRecvable() = %v, want ErrConnectionNotConnected", err)
		}
	})

	t.Run("succeeds once connected", func(t *testing.T) {
		var l connLifecycle
		if err := l.markConnected(); err != nil {
			t.Fatalf("markConnected() = %v, want nil", err)
		}
		if err := l.checkRecvable(); err != nil {
			t.Fatalf("checkRecvable() = %v, want nil", err)
		}
	})

	t.Run("rejects once closed, even if previously connected", func(t *testing.T) {
		var l connLifecycle
		if err := l.markConnected(); err != nil {
			t.Fatalf("markConnected() = %v, want nil", err)
		}
		if _, err := l.markClosed(); err != nil {
			t.Fatalf("markClosed() = %v, want nil", err)
		}
		if err := l.checkRecvable(); !errors.Is(err, ErrConnectionClosed) {
			t.Fatalf("checkRecvable() after close = %v, want ErrConnectionClosed", err)
		}
	})
}
