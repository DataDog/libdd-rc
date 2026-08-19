package ddrc

import (
	"errors"
	"sync"
	"testing"
	"time"

	magictunnelv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel"
)

// newTestConnection returns a connected Connection, and registers cleanup
// that tears it down in the order the client library requires.
func newTestConnection(t *testing.T) *Connection {
	t.Helper()

	ctx, err := Init()
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}

	conn, err := ctx.NewConnection()
	if err != nil {
		t.Fatalf("NewConnection() returned error: %v", err)
	}

	t.Cleanup(func() {
		_ = conn.Disconnected()
		_ = ctx.Close()
	})

	if err := conn.Connected(); err != nil {
		t.Fatalf("Connected() returned error: %v", err)
	}

	return conn
}

// TestConnectionRecvEmptyPayload verifies that an empty payload is rejected
// rather than passed on as a null pointer, which rc_conn_recv asserts
// against before it checks the length, aborting the process.
func TestConnectionRecvEmptyPayload(t *testing.T) {
	conn := newTestConnection(t)

	for _, data := range [][]byte{nil, {}} {
		if err := conn.Recv(data); !errors.Is(err, ErrEmptyPayload) {
			t.Fatalf("Recv(%v) = %v, want ErrEmptyPayload", data, err)
		}
	}
}

// TestConnectionRecvBeforeConnected verifies that Recv on a connection that
// was never marked as connected is reported as an error. rc-x509-client
// panics in this state, which aborts the process.
func TestConnectionRecvBeforeConnected(t *testing.T) {
	ctx, err := Init()
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}
	conn, err := ctx.NewConnection()
	if err != nil {
		t.Fatalf("NewConnection() returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Disconnected()
		_ = ctx.Close()
	})

	if err := conn.Recv([]byte{0x01}); !errors.Is(err, ErrConnectionNotConnected) {
		t.Fatalf("Recv() = %v, want ErrConnectionNotConnected", err)
	}
}

// TestConnectionRecvAfterDisconnected verifies Recv is rejected once the
// connection has been torn down; the FFIConnection has been freed by then.
func TestConnectionRecvAfterDisconnected(t *testing.T) {
	ctx, err := Init()
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}
	defer func() { _ = ctx.Close() }()

	conn, err := ctx.NewConnection()
	if err != nil {
		t.Fatalf("NewConnection() returned error: %v", err)
	}
	if err := conn.Connected(); err != nil {
		t.Fatalf("Connected() returned error: %v", err)
	}
	if err := conn.Disconnected(); err != nil {
		t.Fatalf("Disconnected() returned error: %v", err)
	}

	if err := conn.Recv([]byte{0x01}); !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("Recv() = %v, want ErrConnectionClosed", err)
	}
}

// TestConnectionConnectedTwice verifies the second call is rejected;
// rc-x509-client panics unless the connection is in the configured state.
func TestConnectionConnectedTwice(t *testing.T) {
	conn := newTestConnection(t)

	if err := conn.Connected(); !errors.Is(err, ErrConnectionAlreadyConnected) {
		t.Fatalf("second Connected() = %v, want ErrConnectionAlreadyConnected", err)
	}
}

// newTestInvokePipeline wires up a connState's dispatchQueue/resultQueue and
// starts invokeWorkerCount invoke workers against it, without touching the
// FFI boundary: invokeJob only ever writes to c.st.resultQueue, so these
// tests can drive the goroutine pool directly and inspect resultQueue
// themselves instead of needing a real FFIConnection and resultWorker.
func newTestInvokePipeline(t *testing.T) *Connection {
	t.Helper()

	st := &connState{
		dispatchQueue: make(chan dispatchJob, dispatchQueueCap),
		resultQueue:   make(chan dispatchResult, resultQueueCap),
		stop:          make(chan struct{}),
		accepting:     true,
	}
	conn := &Connection{state: st}

	var poolWG sync.WaitGroup
	poolWG.Add(invokeWorkerCount)
	st.wg.Add(invokeWorkerCount)
	for range invokeWorkerCount {
		go conn.invokeWorker(&poolWG)
	}

	t.Cleanup(func() {
		close(st.stop)
		poolWG.Wait()
	})

	return conn
}

// TestInvokeWorkersOverlapSlowAndFastHandlers verifies that a fast handler's
// result reaches resultQueue while a slow handler queued ahead of it is still
// blocked, proving invocation runs across more than one goroutine rather than
// serializing behind a single worker.
func TestInvokeWorkersOverlapSlowAndFastHandlers(t *testing.T) {
	conn := newTestInvokePipeline(t)

	started := make(chan uint64, 2)
	release := make(chan struct{})

	slow := func(correlationID uint64, _ []byte) ([]byte, error) {
		started <- correlationID
		<-release
		return nil, nil
	}
	fast := func(correlationID uint64, _ []byte) ([]byte, error) {
		started <- correlationID
		return nil, nil
	}

	req := &magictunnelv1.MagicTunnelRequest{}
	conn.state.dispatchQueue <- dispatchJob{correlationID: 1, handler: slow, request: req}
	conn.state.dispatchQueue <- dispatchJob{correlationID: 2, handler: fast, request: req}

	seen := map[uint64]bool{}
	for range 2 {
		select {
		case id := <-started:
			seen[id] = true
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for both handlers to start, seen: %v", seen)
		}
	}
	if !seen[1] || !seen[2] {
		t.Fatalf("started handlers = %v, want both 1 and 2", seen)
	}

	select {
	case result := <-conn.state.resultQueue:
		if result.correlationID != 2 {
			t.Fatalf("first result correlationID = %d, want 2 (fast handler must finish before the slow handler is released)", result.correlationID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the fast handler's result while the slow handler is still blocked")
	}

	close(release)

	select {
	case result := <-conn.state.resultQueue:
		if result.correlationID != 1 {
			t.Fatalf("second result correlationID = %d, want 1", result.correlationID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the slow handler's result after release")
	}
}

// TestInvokeWorkersYieldExactlyOneResultPerJob verifies that every job
// accepted onto dispatchQueue produces exactly one dispatchResult, even when
// a pool of invokeWorkerCount goroutines is processing jobs concurrently.
// libdd_rc.h requires exactly one rc_conn_dispatch_result call per payload,
// so the pool must neither drop nor duplicate a job's result.
func TestInvokeWorkersYieldExactlyOneResultPerJob(t *testing.T) {
	conn := newTestInvokePipeline(t)

	const jobs = 50
	noop := func(uint64, []byte) ([]byte, error) { return nil, nil }
	for i := uint64(1); i <= jobs; i++ {
		conn.state.dispatchQueue <- dispatchJob{correlationID: i, handler: noop, request: &magictunnelv1.MagicTunnelRequest{}}
	}

	seen := map[uint64]int{}
	for range jobs {
		select {
		case result := <-conn.state.resultQueue:
			seen[result.correlationID]++
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for results, got %d of %d", len(seen), jobs)
		}
	}

	for i := uint64(1); i <= jobs; i++ {
		if seen[i] != 1 {
			t.Errorf("correlationID %d yielded %d results, want exactly 1", i, seen[i])
		}
	}

	select {
	case extra := <-conn.state.resultQueue:
		t.Fatalf("unexpected extra result: %+v", extra)
	default:
	}
}

// TestDispatchWorkerDrainsQueueOnDisconnect verifies that payloads already
// queued when the connection is torn down are still handled. libdd_rc.h
// requires exactly one rc_conn_dispatch_result call per payload delivered
// through DispatchCb, so they cannot be discarded once stop is closed.
func TestDispatchWorkerDrainsQueueOnDisconnect(t *testing.T) {
	const ns = magictunnelv1.Namespace_NAMESPACE_REMOTE_CONFIG

	release := make(chan struct{})
	handled := make(chan uint64, 3)

	// Blocks the worker inside the first job, so the remaining jobs are still
	// queued by the time Disconnected runs.
	blocking := func(correlationID uint64, _ []byte) ([]byte, error) {
		handled <- correlationID
		<-release
		return nil, nil
	}
	recording := func(correlationID uint64, _ []byte) ([]byte, error) {
		handled <- correlationID
		return nil, nil
	}

	ctx, err := Init()
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}
	defer func() { _ = ctx.Close() }()

	conn, err := ctx.NewConnection()
	if err != nil {
		t.Fatalf("NewConnection() returned error: %v", err)
	}
	if err := conn.Connected(); err != nil {
		t.Fatalf("Connected() returned error: %v", err)
	}

	newJob := func(correlationID uint64, h HandlerFunc) dispatchJob {
		return dispatchJob{
			correlationID: correlationID,
			handler:       h,
			request:       &magictunnelv1.MagicTunnelRequest{Namespace: ns},
		}
	}

	conn.state.dispatchQueue <- newJob(1, blocking)

	// Wait until the worker is inside the blocking handler before queueing
	// the jobs that must survive teardown.
	select {
	case got := <-handled:
		if got != 1 {
			t.Fatalf("first handled correlationID = %d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the dispatch worker to pick up the first job")
	}

	conn.state.dispatchQueue <- newJob(2, recording)
	conn.state.dispatchQueue <- newJob(3, recording)

	disconnected := make(chan error, 1)
	go func() { disconnected <- conn.Disconnected() }()

	close(release)

	select {
	case err := <-disconnected:
		if err != nil {
			t.Fatalf("Disconnected() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Disconnected to drain the dispatch queue")
	}

	drained := map[uint64]bool{}
	for range 2 {
		select {
		case got := <-handled:
			drained[got] = true
		default:
			t.Fatalf("queued jobs were dropped on teardown, handled: %v", drained)
		}
	}

	if !drained[2] || !drained[3] {
		t.Fatalf("handled correlation IDs = %v, want 2 and 3", drained)
	}
}

// TestDispatchWorkerSurvivesHandlerPanic verifies a panic in caller-supplied
// handler code does not take the dispatch worker with it, which would leave
// every payload behind it unanswered.
func TestDispatchWorkerSurvivesHandlerPanic(t *testing.T) {
	const ns = magictunnelv1.Namespace_NAMESPACE_REMOTE_CONFIG

	conn := newTestConnection(t)

	handled := make(chan uint64, 1)
	panicking := func(uint64, []byte) ([]byte, error) { panic("handler is unwell") }
	recording := func(correlationID uint64, _ []byte) ([]byte, error) {
		handled <- correlationID
		return nil, nil
	}

	for i, h := range []HandlerFunc{panicking, recording} {
		conn.state.dispatchQueue <- dispatchJob{
			correlationID: uint64(i + 1),
			handler:       h,
			request:       &magictunnelv1.MagicTunnelRequest{Namespace: ns},
		}
	}

	select {
	case got := <-handled:
		if got != 2 {
			t.Fatalf("handled correlationID = %d, want 2", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the job queued behind a panicking handler")
	}
}

// TestConnectionRecvConcurrentWithDisconnected drives Recv against a
// concurrent teardown. Recv holds the connection lock across the FFI call, so
// every call must either be accepted before the FFIConnection is freed or
// report the connection as closed; it must never reach the freed handle.
func TestConnectionRecvConcurrentWithDisconnected(t *testing.T) {
	ctx, err := Init()
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}
	defer func() { _ = ctx.Close() }()

	conn, err := ctx.NewConnection()
	if err != nil {
		t.Fatalf("NewConnection() returned error: %v", err)
	}
	if err := conn.Connected(); err != nil {
		t.Fatalf("Connected() returned error: %v", err)
	}

	const senders = 8

	var wg sync.WaitGroup
	start := make(chan struct{})

	for range senders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 32 {
				if err := conn.Recv([]byte{0x01, 0x02}); err != nil && !errors.Is(err, ErrConnectionClosed) {
					t.Errorf("Recv() = %v, want nil or ErrConnectionClosed", err)
					return
				}
			}
		}()
	}

	close(start)
	if err := conn.Disconnected(); err != nil {
		t.Fatalf("Disconnected() returned error: %v", err)
	}
	wg.Wait()
}
