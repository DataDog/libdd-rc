package rcx509

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi"
)

// syncBuffer is a bytes.Buffer safe for concurrent use by the test's copy
// goroutine and the test reading it back.
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

// logSinkTestFile keeps the write end of the test's pipe referenced for the
// remaining lifetime of the process, per EnableLogSink's documented
// requirement that the caller keep the file it passes alive.
var logSinkTestFile *os.File

// TestEnableLogSink verifies that a tracing event emitted after installing
// the sink is observed on the pipe passed to EnableLogSink, and that a
// repeat call is rejected. This has to be one test rather than several:
// EnableLogSink installs a process-global subscriber, so only the first call
// across the whole test binary can ever succeed.
func TestEnableLogSink(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() returned error: %v", err)
	}
	logSinkTestFile = writer

	buf := &syncBuffer{}
	go func() { _, _ = io.Copy(buf, reader) }()

	if err := EnableLogSink(LogLevelDebug, writer); err != nil {
		t.Fatalf("EnableLogSink() returned error: %v", err)
	}

	if err := EnableLogSink(LogLevelDebug, writer); !errors.Is(err, ErrLogSinkAlreadySet) {
		t.Fatalf("second EnableLogSink() = %v, want ErrLogSinkAlreadySet", err)
	}

	ctx, err := libddrcffi.Init("test", "0.0.0")
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
