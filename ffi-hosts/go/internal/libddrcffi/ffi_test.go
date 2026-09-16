package libddrcffi

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	magictunnelv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel"
	protocolv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/protocol"
)

// discardResultSink is a resultSink that drops every result, for tests that
// only need a connState wired up enough for goDispatchCb/goSendCb to run,
// without a running invokePool behind it.
type discardResultSink struct{}

func (discardResultSink) sendDispatchResult(dispatchResult) {}

func newTestConnState() *connState {
	return &connState{
		pool:     newInvokePool(discardResultSink{}),
		outgoing: make(chan []byte, 1),
	}
}

// TestConnStateFromUserData_RoundTripsNewConnectionEncoding verifies that
// connStateFromUserData can decode the user_data value exactly as
// NewConnection constructs it: a pinnedHandle's userData(). The two must
// agree on how a cgo.Handle is packed into a void*, since NewConnection is
// the only place in production code that performs the encode side of that
// contract.
func TestConnStateFromUserData_RoundTripsNewConnectionEncoding(t *testing.T) {
	st := newTestConnState()

	handle := newPinnedHandle(st)
	defer handle.release()

	got, ok := connStateFromUserData(handle.userData())
	if !ok {
		t.Fatal("connStateFromUserData() ok = false, want true")
	}
	if got != st {
		t.Errorf("connStateFromUserData() = %p, want %p", got, st)
	}
}

// encodeDispatchRequest builds a wire-encoded DispatchRequestPayload
// wrapping a MagicTunnelRequest for uri/innerPayload, as goDispatchCb expects
// to receive from Rust.
func encodeDispatchRequest(t *testing.T, uri string, innerPayload []byte) []byte {
	t.Helper()

	encoded, err := proto.Marshal(&protocolv1.DispatchRequestPayload{
		Payload: &protocolv1.DispatchRequestPayload_MagicTunnel{
			MagicTunnel: &magictunnelv1.MagicTunnelRequest{
				Uri:     uri,
				Request: innerPayload,
			},
		},
	})
	if err != nil {
		t.Fatalf("proto.Marshal() returned error: %v", err)
	}
	return encoded
}

func TestGoDispatchCb_EnqueuesAndCopies(t *testing.T) {
	const uri = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"

	if err := RegisterHandler(uri, func(uint64, []byte) ([]byte, error) { return nil, nil }); err != nil {
		t.Fatalf("RegisterHandler(uri) returned error: %v", err)
	}
	defer func() { _ = UnregisterHandler(uri) }()

	st := newTestConnState()
	u := newTestUserData(st)
	defer u.free()

	innerPayload := []byte{0xde, 0xad, 0xbe, 0xef}
	payload := encodeDispatchRequest(t, uri, innerPayload)

	ret := callGoDispatchCb(42, payload, u)
	if ret != testDispatchRetSuccess {
		t.Fatalf("goDispatchCb() = %v, want testDispatchRetSuccess", ret)
	}

	select {
	case job := <-st.pool.dispatchQueue:
		if job.correlationID != 42 {
			t.Errorf("job.correlationID = %d, want 42", job.correlationID)
		}
		if job.request.GetUri() != uri {
			t.Errorf("job.request.GetUri() = %v, want %v", job.request.GetUri(), uri)
		}
		if string(job.request.GetRequest()) != string(innerPayload) {
			t.Errorf("job.request.GetRequest() = %v, want %v", job.request.GetRequest(), innerPayload)
		}
		if job.handler == nil {
			t.Error("job.handler = nil, want the registered handler")
		}
	default:
		t.Fatal("expected a job to be enqueued")
	}
}

// TestDispatchRequestPayload_UnmarshalCopiesInnerBytes verifies that
// proto.Unmarshal copies bytes-field contents rather than aliasing the wire
// buffer it was given. goDispatchCb already copies via C.GoBytes before
// calling proto.Unmarshal, so this test unmarshals directly to answer the
// question about proto's own guarantee, independent of that cgo copy.
func TestDispatchRequestPayload_UnmarshalCopiesInnerBytes(t *testing.T) {
	const uri = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"

	innerPayload := []byte{0xde, 0xad, 0xbe, 0xef}
	want := append([]byte(nil), innerPayload...)

	wire := encodeDispatchRequest(t, uri, innerPayload)

	var req protocolv1.DispatchRequestPayload
	if err := proto.Unmarshal(wire, &req); err != nil {
		t.Fatalf("proto.Unmarshal() returned error: %v", err)
	}

	for i := range wire {
		wire[i] = 0xff
	}

	if got := req.GetMagicTunnel().GetRequest(); string(got) != string(want) {
		t.Errorf("req.GetMagicTunnel().GetRequest() = %v after mutating wire buffer, want %v (unchanged)", got, want)
	}
}

func TestGoDispatchCb_UnknownPayload(t *testing.T) {
	st := newTestConnState()
	u := newTestUserData(st)
	defer u.free()

	ret := callGoDispatchCb(1, []byte{0xff, 0xff, 0xff}, u)
	if ret != testDispatchRetUnknownPayload {
		t.Fatalf("goDispatchCb() = %v, want testDispatchRetUnknownPayload", ret)
	}

	select {
	case job := <-st.pool.dispatchQueue:
		t.Fatalf("expected no job to be enqueued, got %+v", job)
	default:
	}
}

func TestGoDispatchCb_NoDispatchHandler(t *testing.T) {
	const uri = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"

	// Ensure no handler is registered for uri.
	_ = UnregisterHandler(uri)

	st := newTestConnState()
	u := newTestUserData(st)
	defer u.free()

	payload := encodeDispatchRequest(t, uri, []byte{0x01})

	ret := callGoDispatchCb(1, payload, u)
	if ret != testDispatchRetNoDispatchHandler {
		t.Fatalf("goDispatchCb() = %v, want testDispatchRetNoDispatchHandler", ret)
	}

	select {
	case job := <-st.pool.dispatchQueue:
		t.Fatalf("expected no job to be enqueued, got %+v", job)
	default:
	}
}

func TestGoDispatchCb_QueueFull(t *testing.T) {
	const uri = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"

	if err := RegisterHandler(uri, func(uint64, []byte) ([]byte, error) { return nil, nil }); err != nil {
		t.Fatalf("RegisterHandler(uri) returned error: %v", err)
	}
	defer func() { _ = UnregisterHandler(uri) }()

	st := newTestConnState()
	u := newTestUserData(st)
	defer u.free()

	// Fill dispatchQueue to capacity directly, then the callback must return
	// QUEUE_FULL instead of blocking.
	for i := 0; i < cap(st.pool.dispatchQueue); i++ {
		st.pool.dispatchQueue <- dispatchJob{correlationID: uint64(i)}
	}

	payload := encodeDispatchRequest(t, uri, []byte{0x01})

	ret := callGoDispatchCb(2, payload, u)
	if ret != testDispatchRetQueueFull {
		t.Fatalf("goDispatchCb() = %v, want testDispatchRetQueueFull", ret)
	}
}

// TestGoDispatchCb_RejectsWhenNotAccepting verifies that a payload arriving
// once the connection has stopped accepting work is refused outright. It
// would otherwise be accepted with DISPATCH_RET_SUCCESS and then abandoned,
// since no dispatch worker is left to answer it.
func TestGoDispatchCb_RejectsWhenNotAccepting(t *testing.T) {
	const uri = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"

	if err := RegisterHandler(uri, func(uint64, []byte) ([]byte, error) { return nil, nil }); err != nil {
		t.Fatalf("RegisterHandler(uri) returned error: %v", err)
	}
	defer func() { _ = UnregisterHandler(uri) }()

	st := newTestConnState()
	st.pool.accepting = false

	u := newTestUserData(st)
	defer u.free()

	ret := callGoDispatchCb(1, encodeDispatchRequest(t, uri, []byte{0x01}), u)
	if ret != testDispatchRetQueueFull {
		t.Fatalf("goDispatchCb() = %v, want testDispatchRetQueueFull", ret)
	}

	select {
	case job := <-st.pool.dispatchQueue:
		t.Fatalf("expected no job to be enqueued, got %+v", job)
	default:
	}
}

func TestGoDispatchCb_UnknownUserData(t *testing.T) {
	ret := callGoDispatchCb(1, nil, nil)
	if ret != testDispatchRetUnknown {
		t.Fatalf("goDispatchCb() = %v, want testDispatchRetUnknown", ret)
	}
}

// TestGoDispatchCb_StaleUserData verifies that a user_data value naming an
// already-released cgo.Handle is reported as an error rather than aborting
// the process: cgo.Handle.Value() panics on a deleted handle, and a panic
// cannot cross back into the non-unwinding Rust caller.
func TestGoDispatchCb_StaleUserData(t *testing.T) {
	st := newTestConnState()
	u := newTestUserData(st)
	u.free()

	ret := callGoDispatchCb(1, nil, u)
	if ret != testDispatchRetUnknown {
		t.Fatalf("goDispatchCb() = %v, want testDispatchRetUnknown", ret)
	}
}

// TestGoSendCb_StaleUserData is the goSendCb counterpart to
// TestGoDispatchCb_StaleUserData.
func TestGoSendCb_StaleUserData(t *testing.T) {
	st := newTestConnState()
	u := newTestUserData(st)
	u.free()

	ret := callGoSendCb([]byte{0x01}, u)
	if ret != testSendRetUnknown {
		t.Fatalf("goSendCb() = %v, want testSendRetUnknown", ret)
	}
}

func TestGoSendCb_EnqueuesAndCopies(t *testing.T) {
	st := newTestConnState()
	u := newTestUserData(st)
	defer u.free()

	payload := []byte{0x01, 0x02, 0x03}

	ret := callGoSendCb(payload, u)
	if ret != testSendRetSuccess {
		t.Fatalf("goSendCb() = %v, want testSendRetSuccess", ret)
	}

	select {
	case got := <-st.outgoing:
		if string(got) != string(payload) {
			t.Errorf("outgoing payload = %v, want %v", got, payload)
		}
	default:
		t.Fatal("expected a payload to be enqueued on outgoing")
	}
}

func TestGoSendCb_QueueFull(t *testing.T) {
	st := newTestConnState()
	u := newTestUserData(st)
	defer u.free()

	st.outgoing <- []byte{0x00}

	ret := callGoSendCb(nil, u)
	if ret != testSendRetUnknown {
		t.Fatalf("goSendCb() = %v, want testSendRetUnknown", ret)
	}
}

// TestDispatchWorker_RoutesToHandler drives a real Connection (so
// handleDispatchJob's call into rc_conn_dispatch_result has a valid conn
// pointer) and injects a job directly into the dispatch queue, since Main
// never organically calls DispatchCb today. It only asserts the registered
// handler is actually invoked with the expected arguments; it cannot observe
// rc_conn_dispatch_result's effect on the no-op Main.
func TestDispatchWorker_RoutesToHandler(t *testing.T) {
	const uri = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"

	type invocation struct {
		correlationID uint64
		payload       []byte
	}
	called := make(chan invocation, 1)
	handler := func(correlationID uint64, payload []byte) ([]byte, error) {
		called <- invocation{correlationID: correlationID, payload: payload}
		return []byte{0xaa, 0xbb}, nil
	}
	if err := RegisterHandler(uri, handler); err != nil {
		t.Fatalf("RegisterHandler(uri) returned error: %v", err)
	}
	defer func() { _ = UnregisterHandler(uri) }()

	ctx, err := Init("test", "0.0.0")
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}
	defer func() { _ = ctx.Close() }()

	conn, err := ctx.NewConnection()
	if err != nil {
		t.Fatalf("NewConnection() returned error: %v", err)
	}
	defer func() { _ = conn.Close() }()

	innerPayload := []byte{0x01}
	job := dispatchJob{
		correlationID: 7,
		handler:       handler,
		request:       &magictunnelv1.MagicTunnelRequest{Uri: uri, Request: innerPayload},
	}
	conn.state.pool.dispatchQueue <- job

	select {
	case got := <-called:
		if got.correlationID != job.correlationID || string(got.payload) != string(innerPayload) {
			t.Fatalf("handler called with %+v, want correlationID=%d payload=%v", got, job.correlationID, innerPayload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for dispatch worker to route job to handler")
	}
}
