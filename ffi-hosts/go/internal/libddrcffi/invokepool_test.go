package libddrcffi

import (
	"context"
	"testing"
	"time"

	magictunnelv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel"
)

// testHandlerTimeout is short enough to keep timeout tests fast, but long
// enough that a handler which is supposed to finish promptly reliably beats it
const testHandlerTimeout = 20 * time.Millisecond

// newTimeoutTestPipeline is newTestInvokePipeline with handlerTimeout
// overridden to testHandlerTimeout, so the timeout path can be exercised
// without waiting on defaultHandlerTimeout.
func newTimeoutTestPipeline(t *testing.T) (*invokePool, chanResultSink) {
	t.Helper()

	sink := newChanResultSink()
	pool := newInvokePool(sink)
	pool.handlerTimeout = testHandlerTimeout

	pool.start()
	t.Cleanup(pool.shutdown)

	return pool, sink
}

// TestInvokeHandler_TimeoutReportsDispatchErrorNotResult verifies that once a
// handler exceeds handlerTimeout, the pool reports a dispatch error and, even
// after the handler eventually returns, never also delivers a dispatch
// result for the same job. rc_conn_dispatch_result must be called exactly
// once per payload; the timeout path and the normal-completion path must not
// both fire.
func TestInvokeHandler_TimeoutReportsDispatchErrorNotResult(t *testing.T) {
	pool, sink := newTimeoutTestPipeline(t)

	release := make(chan struct{})
	blocked := func(_ context.Context, correlationID uint64, _ []byte) ([]byte, error) {
		<-release
		return []byte{0xaa}, nil
	}

	pool.enqueue(dispatchJob{correlationID: 1, handler: blocked, request: &magictunnelv1.MagicTunnelRequest{}})

	select {
	case err := <-sink.errors:
		if err.correlationID != 1 {
			t.Fatalf("dispatch error correlationID = %d, want 1", err.correlationID)
		}
		if err.errorCode != DispatchErrorTimeout {
			t.Fatalf("dispatch error errorCode = %d, want %d (DispatchErrorTimeout)", err.errorCode, DispatchErrorTimeout)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for dispatch error")
	}

	close(release)

	select {
	case result := <-sink.results:
		t.Fatalf("unexpected dispatch result after timeout: %+v", result)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestInvokeHandler_CompletesBeforeTimeout verifies a handler that finishes
// within handlerTimeout is reported as a normal dispatch result, with no
// dispatch error sent.
func TestInvokeHandler_CompletesBeforeTimeout(t *testing.T) {
	pool, sink := newTimeoutTestPipeline(t)

	fast := func(_ context.Context, correlationID uint64, _ []byte) ([]byte, error) {
		return []byte{0xbb}, nil
	}

	pool.enqueue(dispatchJob{correlationID: 2, handler: fast, request: &magictunnelv1.MagicTunnelRequest{}})

	select {
	case result := <-sink.results:
		if result.correlationID != 2 {
			t.Fatalf("result correlationID = %d, want 2", result.correlationID)
		}
		if result.err != nil {
			t.Fatalf("result.err = %v, want nil", result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for dispatch result")
	}

	select {
	case err := <-sink.errors:
		t.Fatalf("unexpected dispatch error for handler that completed in time: %+v", err)
	default:
	}
}

// TestInvokeHandler_ContextCanceledOnTimeout verifies the context passed to
// the handler is the one enforcing handlerTimeout, so a HandlerFunc that
// checks ctx.Done() can observe the deadline itself. A handler that returns
// promptly on cancellation races the background timeout watcher for which of
// them reports the outcome, so exactly one of a dispatch error or a dispatch
// result carrying ctx.Err() must arrive, never neither or both.
func TestInvokeHandler_ContextCanceledOnTimeout(t *testing.T) {
	pool, sink := newTimeoutTestPipeline(t)

	observedErr := make(chan error, 1)
	handler := func(ctx context.Context, _ uint64, _ []byte) ([]byte, error) {
		<-ctx.Done()
		observedErr <- ctx.Err()
		return nil, ctx.Err()
	}

	pool.enqueue(dispatchJob{correlationID: 3, handler: handler, request: &magictunnelv1.MagicTunnelRequest{}})

	select {
	case err := <-observedErr:
		if err != context.DeadlineExceeded {
			t.Fatalf("ctx.Err() = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handler to observe context cancellation")
	}

	select {
	case dispatchErr := <-sink.errors:
		if dispatchErr.errorCode != DispatchErrorTimeout {
			t.Fatalf("dispatch error errorCode = %d, want %d (DispatchErrorTimeout)", dispatchErr.errorCode, DispatchErrorTimeout)
		}
	case result := <-sink.results:
		if result.err != context.DeadlineExceeded {
			t.Fatalf("result.err = %v, want context.DeadlineExceeded", result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a dispatch error or dispatch result")
	}

	select {
	case dispatchErr := <-sink.errors:
		t.Fatalf("unexpected second report (dispatch error): %+v", dispatchErr)
	case result := <-sink.results:
		t.Fatalf("unexpected second report (dispatch result): %+v", result)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestInvokeHandler_PanicAfterTimeoutDoesNotDoubleReport verifies that a
// handler which panics after handlerTimeout has already elapsed does not
// produce a second report on top of the dispatch error the timeout already
// sent; each job gets exactly one outcome delivered to the sink.
func TestInvokeHandler_PanicAfterTimeoutDoesNotDoubleReport(t *testing.T) {
	pool, sink := newTimeoutTestPipeline(t)

	release := make(chan struct{})
	panicsLate := func(_ context.Context, _ uint64, _ []byte) ([]byte, error) {
		<-release
		panic("handler is unwell, but only after the deadline")
	}

	pool.enqueue(dispatchJob{correlationID: 4, handler: panicsLate, request: &magictunnelv1.MagicTunnelRequest{}})

	select {
	case err := <-sink.errors:
		if err.errorCode != DispatchErrorTimeout {
			t.Fatalf("dispatch error errorCode = %d, want %d (DispatchErrorTimeout)", err.errorCode, DispatchErrorTimeout)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for dispatch error")
	}

	close(release)

	select {
	case result := <-sink.results:
		t.Fatalf("unexpected dispatch result after late panic: %+v", result)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestInvokeHandler_PanicBeforeTimeoutReportsAsDispatchResult verifies a
// handler that panics before handlerTimeout elapses is reported through the
// normal dispatch result path with a panic error, not as a dispatch timeout,
// distinguishing this from the late-panic case above.
func TestInvokeHandler_PanicBeforeTimeoutReportsAsDispatchResult(t *testing.T) {
	pool, sink := newTimeoutTestPipeline(t)

	panicsImmediately := func(_ context.Context, _ uint64, _ []byte) ([]byte, error) {
		panic("handler is unwell")
	}

	pool.enqueue(dispatchJob{correlationID: 5, handler: panicsImmediately, request: &magictunnelv1.MagicTunnelRequest{}})

	select {
	case result := <-sink.results:
		if result.correlationID != 5 {
			t.Fatalf("result correlationID = %d, want 5", result.correlationID)
		}
		if result.err == nil {
			t.Fatal("result.err = nil, want a panic error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for dispatch result")
	}

	select {
	case err := <-sink.errors:
		t.Fatalf("unexpected dispatch error for handler that panicked before the deadline: %+v", err)
	default:
	}
}

// TestShutdown_DoesNotBlockOnRogueHandler verifies shutdown does not wait for
// a HandlerFunc that never returns and ignores its context: the invoke
// worker goroutine calling it is left running, but shutdown still completes
// once the timeout watcher has reported the dispatch error, well within the
// pool's handlerTimeout.
func TestShutdown_DoesNotBlockOnRogueHandler(t *testing.T) {
	sink := newChanResultSink()
	pool := newInvokePool(sink)
	pool.handlerTimeout = testHandlerTimeout
	pool.start()

	rogue := func(_ context.Context, _ uint64, _ []byte) ([]byte, error) {
		select {}
	}

	pool.enqueue(dispatchJob{correlationID: 6, handler: rogue, request: &magictunnelv1.MagicTunnelRequest{}})

	select {
	case err := <-sink.errors:
		if err.errorCode != DispatchErrorTimeout {
			t.Fatalf("dispatch error errorCode = %d, want %d (DispatchErrorTimeout)", err.errorCode, DispatchErrorTimeout)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for dispatch error")
	}

	done := make(chan struct{})
	go func() {
		pool.shutdown()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown blocked on a worker stuck in a HandlerFunc that never returns")
	}
}
