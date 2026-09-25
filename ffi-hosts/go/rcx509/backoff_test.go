package rcx509

import (
	"testing"
	"time"
)

// TestBackoffNextGrowsAndCapsAtMax exercises the exponential growth of Next,
// confirming each delay falls within the jittered range implied by the
// backoff's parameters, and that growth stops once max is reached.
func TestBackoffNextGrowsAndCapsAtMax(t *testing.T) {
	b := newBackoff(defaultInitialBackoff, defaultMaxBackoff, defaultBackoffMultiplier)

	assertInRange(t, b.Next(), 500*time.Millisecond, 1*time.Second) // base 1s
	assertInRange(t, b.Next(), 1*time.Second, 2*time.Second)        // base 2s
	assertInRange(t, b.Next(), 2*time.Second, 4*time.Second)        // base 4s
	assertInRange(t, b.Next(), 4*time.Second, 8*time.Second)        // base 8s
	assertInRange(t, b.Next(), 8*time.Second, 16*time.Second)       // base 16s
	assertInRange(t, b.Next(), 15*time.Second, 30*time.Second)      // base 32s, capped at 30s
	assertInRange(t, b.Next(), 15*time.Second, 30*time.Second)      // base 64s, capped at 30s
}

// TestBackoffResetReturnsToInitialRange confirms that Reset undoes prior
// growth, so the next delay is back in the initial jittered range.
func TestBackoffResetReturnsToInitialRange(t *testing.T) {
	b := newBackoff(defaultInitialBackoff, defaultMaxBackoff, defaultBackoffMultiplier)

	b.Next()
	b.Next()
	b.Next()

	b.Reset()

	assertInRange(t, b.Next(), 500*time.Millisecond, 1*time.Second)
}

func assertInRange(t *testing.T, got, min, max time.Duration) {
	t.Helper()
	if got < min || got > max {
		t.Fatalf("delay %v not in expected range [%v, %v]", got, min, max)
	}
}
