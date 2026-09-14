package rcx509

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi"
)

// syncBuffer is a bytes.Buffer safe for concurrent use by EnableLogSink's
// background copy goroutine and a test reading it back.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestEnableLogSink verifies that a tracing event emitted after installing
// the sink is observed on the provided io.Writer, and that a repeat call is
// rejected. This has to be one test rather than several: EnableLogSink
// installs a process-global subscriber, so only the first call across the
// whole test binary can ever succeed.
func TestEnableLogSink(t *testing.T) {
	buf := &syncBuffer{}

	if err := EnableLogSink(LogLevelDebug, buf); err != nil {
		t.Fatalf("EnableLogSink() returned error: %v", err)
	}

	if err := EnableLogSink(LogLevelDebug, buf); !errors.Is(err, ErrLogSinkAlreadySet) {
		t.Fatalf("second EnableLogSink() = %v, want ErrLogSinkAlreadySet", err)
	}

	ctx, err := libddrcffi.Init()
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}
	defer func() { _ = ctx.Close() }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if strings.Contains(buf.String(), "rc_x509_client") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("log sink output = %q, want a formatted rc_x509_client tracing event", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
