package rcx509

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/internal/libddrcffi"
)

// TestEnableLogSink exercises the full EnableLogSink contract in a single
// test: a valid install succeeds and its fd stays open for later reads, and
// a repeat call is rejected without disturbing the fd it was given.
func TestEnableLogSink(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() returned error: %v", err)
	}
	defer reader.Close()

	if err := EnableLogSink(writer); err != nil {
		t.Fatalf("EnableLogSink() returned error: %v", err)
	}

	_, secondWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() returned error: %v", err)
	}
	defer secondWriter.Close()

	if err := EnableLogSink(secondWriter); !errors.Is(err, libddrcffi.ErrLogSinkAlreadySet) {
		t.Fatalf("second EnableLogSink() = %v, want ErrLogSinkAlreadySet", err)
	}

	if _, err := NewClient("wss://example.invalid/ws", "test", "0.0.0"); err != nil {
		t.Fatalf("NewClient() returned error: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("Read() from log sink pipe returned error: %v", err)
	}
	// Match on the module path rather than a specific message: any of
	// several startup events may win the race to be first through the pipe.
	if !strings.Contains(string(buf[:n]), "rc_x509_client") {
		t.Fatalf("log sink output = %q, want a formatted rc_x509_client tracing event", string(buf[:n]))
	}
}
