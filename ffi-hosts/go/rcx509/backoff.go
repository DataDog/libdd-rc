package rcx509

import (
	"math"
	"math/rand/v2"
	"time"
)

const (
	// defaultInitialBackoff is the delay before the first retry after a
	// connection attempt fails.
	defaultInitialBackoff = 1 * time.Second

	// defaultMaxBackoff caps the delay between reconnection attempts.
	defaultMaxBackoff = 30 * time.Second

	// defaultBackoffMultiplier is how much the base delay grows after each
	// failed attempt.
	defaultBackoffMultiplier = 2.0
)

// backoff computes exponentially increasing, jittered delays between
// reconnection attempts. It is not safe for concurrent use.
type backoff struct {
	initial    time.Duration
	max        time.Duration
	multiplier float64
	attempt    int
}

// newBackoff creates a backoff starting at initial, growing by multiplier
// each attempt, and capped at max.
func newBackoff(initial, max time.Duration, multiplier float64) *backoff {
	return &backoff{initial: initial, max: max, multiplier: multiplier}
}

// Next returns the delay to wait before the next reconnection attempt, and
// advances the backoff to the following attempt.
//
// The delay grows exponentially with the attempt count, up to max, and is
// jittered so that half of it is fixed and half is randomized: this
// guarantees a floor on the delay while still avoiding many clients
// retrying in lockstep.
func (b *backoff) Next() time.Duration {
	d := float64(b.initial) * math.Pow(b.multiplier, float64(b.attempt))
	if d > float64(b.max) {
		d = float64(b.max)
	}
	b.attempt++

	return time.Duration(d/2 + rand.Float64()*d/2)
}

// Reset zeroes the attempt count, so the next call to Next returns a delay
// near the initial one. This is used when a connection was healthy enough
// that its failure shouldn't be held against the next reconnection attempt.
func (b *backoff) Reset() {
	b.attempt = 0
}
