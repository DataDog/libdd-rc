package main

import (
	"fmt"
	"sync"
	"testing"
	"time"

	remotequeriesv1alpha1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_queries"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// remoteQueriesManualClock is a fake clock for deterministic timestamp
// assertions in tests.
type remoteQueriesManualClock struct {
	mu sync.Mutex
	t  time.Time
}

func newRemoteQueriesManualClock() *remoteQueriesManualClock {
	return &remoteQueriesManualClock{t: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)}
}

// Now reports the frozen time.
func (m *remoteQueriesManualClock) Now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.t
}

// Advance moves the frozen time forward by d.
func (m *remoteQueriesManualClock) Advance(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t = m.t.Add(d)
}

// remoteQueriesBool returns a pointer to b, for proto optional bool fields.
func remoteQueriesBool(b bool) *bool {
	return &b
}

// newRemoteQueriesTestController returns an instance-owned controller with a
// manually advanced clock, for deterministic tests.
func newRemoteQueriesTestController() (*remoteQueriesController, *remoteQueriesManualClock) {
	clock := newRemoteQueriesManualClock()
	return &remoteQueriesController{
		runs: make(map[remoteQueriesRunKey]*remoteQueriesRunEntry),
		now:  clock.Now,
	}, clock
}

// remoteQueriesValidResolveTargetRequest returns a structurally valid
// ResolveTargetRequest.
func remoteQueriesValidResolveTargetRequest() *remotequeriesv1alpha1.ResolveTargetRequest {
	return &remotequeriesv1alpha1.ResolveTargetRequest{
		ConnectionId: "conn-remote-queries-1",
		Reason:       "control-plane reference test",
		Integration:  "postgres",
		Target: &remotequeriesv1alpha1.DatabaseTarget{
			Target: &remotequeriesv1alpha1.DatabaseTarget_NetworkTarget{
				NetworkTarget: &remotequeriesv1alpha1.NetworkTarget{
					Host:   "db-a1.internal",
					Port:   5432,
					Dbname: "orders",
				},
			},
		},
	}
}

// remoteQueriesValidStartRunRequest returns a structurally valid
// StartRunRequest with a stable identity.
func remoteQueriesValidStartRunRequest() *remotequeriesv1alpha1.StartRunRequest {
	return &remotequeriesv1alpha1.StartRunRequest{
		ConnectionId: "conn-remote-queries-1",
		Reason:       "control-plane reference test",
		RunIdentity:  remoteQueriesTestRunIdentity(),
		Integration:  "postgres",
		Target: &remotequeriesv1alpha1.DatabaseTarget{
			Target: &remotequeriesv1alpha1.DatabaseTarget_NetworkTarget{
				NetworkTarget: &remotequeriesv1alpha1.NetworkTarget{
					Host:   "db-a1.internal",
					Port:   5432,
					Dbname: "orders",
				},
			},
		},
		Query:         "SELECT count(*) FROM public.orders",
		IncludeSchema: remoteQueriesBool(true),
		ResultDelivery: &remotequeriesv1alpha1.ResultDelivery{
			ArtifactVersion: 1,
			IntakeBaseUrl:   "https://its-agent-intake.example.internal",
			Limits: &remotequeriesv1alpha1.ResultDeliveryLimits{
				MaxFileBytes:   128 * 1024 * 1024,
				MaxResultBytes: 10 * 1024 * 1024 * 1024,
				MaxRowBytes:    8 * 1024 * 1024,
				MaxColumns:     1000,
				MaxSchemaBytes: 1024 * 1024,
				MaxPages:       128,
				TimeoutMs:      300000,
			},
		},
	}
}

// remoteQueriesTestRunIdentity returns the stable identity used by
// remoteQueriesValidStartRunRequest.
func remoteQueriesTestRunIdentity() *remotequeriesv1alpha1.RunIdentity {
	return &remotequeriesv1alpha1.RunIdentity{
		OrgId:    620250,
		TaskId:   "603f58a7-04cf-4ffe-860b-3885457f885c",
		RunId:    "383d34aa-0766-472f-9e27-9190d9a52ab6",
		UploadId: "2f3b0f11-7c3a-4d09-9e61-4c6a2b8d1e57",
	}
}

// marshalRemoteQueriesRequest marshals a request, failing the test on error.
func marshalRemoteQueriesRequest(t *testing.T, req proto.Message) []byte {
	t.Helper()
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return payload
}

// callRemoteQueriesHandler invokes a handler and fails the test when it
// returns an error.
func callRemoteQueriesHandler(t *testing.T, h func(uint64, []byte) ([]byte, error), req proto.Message) []byte {
	t.Helper()
	respBytes, err := h(1, marshalRemoteQueriesRequest(t, req))
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	return respBytes
}

// resolveTarget drives the ResolveTarget handler with a valid-request
// expectation.
func resolveTarget(t *testing.T, c *remoteQueriesController, req *remotequeriesv1alpha1.ResolveTargetRequest) *remotequeriesv1alpha1.ResolveTargetResponse {
	t.Helper()
	var resp remotequeriesv1alpha1.ResolveTargetResponse
	if err := proto.Unmarshal(callRemoteQueriesHandler(t, c.handleResolveTarget, req), &resp); err != nil {
		t.Fatalf("unmarshal ResolveTargetResponse: %v", err)
	}
	return &resp
}

// startRun drives the StartRun handler.
func startRun(t *testing.T, c *remoteQueriesController, req *remotequeriesv1alpha1.StartRunRequest) *remotequeriesv1alpha1.StartRunResponse {
	t.Helper()
	var resp remotequeriesv1alpha1.StartRunResponse
	if err := proto.Unmarshal(callRemoteQueriesHandler(t, c.handleStartRun, req), &resp); err != nil {
		t.Fatalf("unmarshal StartRunResponse: %v", err)
	}
	return &resp
}

// getRunStatus drives the GetRunStatus handler.
func getRunStatus(t *testing.T, c *remoteQueriesController, req *remotequeriesv1alpha1.GetRunStatusRequest) *remotequeriesv1alpha1.GetRunStatusResponse {
	t.Helper()
	var resp remotequeriesv1alpha1.GetRunStatusResponse
	if err := proto.Unmarshal(callRemoteQueriesHandler(t, c.handleGetRunStatus, req), &resp); err != nil {
		t.Fatalf("unmarshal GetRunStatusResponse: %v", err)
	}
	return &resp
}

// cancelRun drives the CancelRun handler.
func cancelRun(t *testing.T, c *remoteQueriesController, req *remotequeriesv1alpha1.CancelRunRequest) *remotequeriesv1alpha1.CancelRunResponse {
	t.Helper()
	var resp remotequeriesv1alpha1.CancelRunResponse
	if err := proto.Unmarshal(callRemoteQueriesHandler(t, c.handleCancelRun, req), &resp); err != nil {
		t.Fatalf("unmarshal CancelRunResponse: %v", err)
	}
	return &resp
}

// newGetRunStatusRequest builds a status lookup for the test identity.
func newGetRunStatusRequest() *remotequeriesv1alpha1.GetRunStatusRequest {
	return &remotequeriesv1alpha1.GetRunStatusRequest{
		ConnectionId: "conn-remote-queries-1",
		Reason:       "control-plane reference test",
		RunIdentity:  remoteQueriesTestRunIdentity(),
	}
}

// newCancelRunRequest builds a cancellation request for the test identity.
func newCancelRunRequest() *remotequeriesv1alpha1.CancelRunRequest {
	return &remotequeriesv1alpha1.CancelRunRequest{
		ConnectionId: "conn-remote-queries-1",
		Reason:       "control-plane reference test",
		RunIdentity:  remoteQueriesTestRunIdentity(),
	}
}

// TestRemoteQueriesControlServiceURIs guards the fully-qualified method URIs
// the handlers are registered under against typos and drift.
func TestRemoteQueriesControlServiceURIs(t *testing.T) {
	const service = "rc.x509.magic_tunnel.remote_queries.v1alpha1.RemoteQueriesControlService/"
	uris := map[string]bool{
		remoteQueriesResolveTargetURI: false,
		remoteQueriesStartRunURI:      false,
		remoteQueriesGetRunStatusURI:  false,
		remoteQueriesCancelRunURI:     false,
	}
	if len(uris) != 4 {
		t.Fatalf("expected four distinct URIs, got %d", len(uris))
	}
	for uri := range uris {
		if len(uri) <= len(service) || uri[:len(service)] != service {
			t.Errorf("URI %q is not under the fully-qualified control service name", uri)
		}
	}
}

// TestHandleResolveTarget covers the valid simulated resolve and the
// malformed/invalid target handling.
func TestHandleResolveTarget(t *testing.T) {
	controller, _ := newRemoteQueriesTestController()

	t.Run("valid network target", func(t *testing.T) {
		resp := resolveTarget(t, controller, remoteQueriesValidResolveTargetRequest())
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.ResolveTargetStatus_RESOLVE_TARGET_STATUS_MATCHED {
			t.Errorf("expected MATCHED, got %s", got)
		}
		if resp.GetError() != nil {
			t.Errorf("expected no error detail, got %v", resp.GetError())
		}
	})

	t.Run("valid database instance", func(t *testing.T) {
		req := remoteQueriesValidResolveTargetRequest()
		req.Target = &remotequeriesv1alpha1.DatabaseTarget{
			Target: &remotequeriesv1alpha1.DatabaseTarget_DatabaseInstance{DatabaseInstance: "orders-primary"},
		}
		resp := resolveTarget(t, controller, req)
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.ResolveTargetStatus_RESOLVE_TARGET_STATUS_MATCHED {
			t.Errorf("expected MATCHED, got %s", got)
		}
	})

	t.Run("invalid targets", func(t *testing.T) {
		reqs := map[string]*remotequeriesv1alpha1.ResolveTargetRequest{
			"missing target":       {Integration: "postgres", Target: nil},
			"empty oneof":          {Integration: "postgres", Target: &remotequeriesv1alpha1.DatabaseTarget{}},
			"nil network target":   {Integration: "postgres", Target: &remotequeriesv1alpha1.DatabaseTarget{Target: &remotequeriesv1alpha1.DatabaseTarget_NetworkTarget{}}},
			"empty host":           {Integration: "postgres", Target: remoteQueriesTargetWithHost("")},
			"zero port":            {Integration: "postgres", Target: remoteQueriesTargetWithPort(0)},
			"port out of range":    {Integration: "postgres", Target: remoteQueriesTargetWithPort(65536)},
			"empty dbname":         {Integration: "postgres", Target: remoteQueriesTargetWithDbname("")},
			"empty database inst.": {Integration: "postgres", Target: &remotequeriesv1alpha1.DatabaseTarget{Target: &remotequeriesv1alpha1.DatabaseTarget_DatabaseInstance{}}},
		}
		for name, req := range reqs {
			req.ConnectionId = "conn-remote-queries-1"
			req.Reason = "control-plane reference test"
			resp := resolveTarget(t, controller, req)
			if got := resp.GetStatus(); got != remotequeriesv1alpha1.ResolveTargetStatus_RESOLVE_TARGET_STATUS_RESOLUTION_ERROR {
				t.Errorf("%s: expected RESOLUTION_ERROR, got %s", name, got)
			}
			if got := resp.GetError().GetCode(); got != remoteQueriesErrInvalidTarget {
				t.Errorf("%s: expected INVALID_TARGET code, got %q", name, got)
			}
		}
	})

	t.Run("missing reason", func(t *testing.T) {
		req := remoteQueriesValidResolveTargetRequest()
		req.Reason = "   "
		resp := resolveTarget(t, controller, req)
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.ResolveTargetStatus_RESOLVE_TARGET_STATUS_RESOLUTION_ERROR {
			t.Errorf("expected RESOLUTION_ERROR, got %s", got)
		}
		if got := resp.GetError().GetCode(); got != remoteQueriesErrMissingReason {
			t.Errorf("expected MISSING_REASON code, got %q", got)
		}
	})

	t.Run("empty integration", func(t *testing.T) {
		req := remoteQueriesValidResolveTargetRequest()
		req.Integration = ""
		resp := resolveTarget(t, controller, req)
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.ResolveTargetStatus_RESOLVE_TARGET_STATUS_RESOLUTION_ERROR {
			t.Errorf("expected RESOLUTION_ERROR, got %s", got)
		}
		if got := resp.GetError().GetCode(); got != remoteQueriesErrInvalidIntegration {
			t.Errorf("expected INVALID_INTEGRATION code, got %q", got)
		}
	})
}

func remoteQueriesTargetWithHost(host string) *remotequeriesv1alpha1.DatabaseTarget {
	return &remotequeriesv1alpha1.DatabaseTarget{
		Target: &remotequeriesv1alpha1.DatabaseTarget_NetworkTarget{
			NetworkTarget: &remotequeriesv1alpha1.NetworkTarget{Host: host, Port: 5432, Dbname: "orders"},
		},
	}
}

func remoteQueriesTargetWithPort(port uint32) *remotequeriesv1alpha1.DatabaseTarget {
	return &remotequeriesv1alpha1.DatabaseTarget{
		Target: &remotequeriesv1alpha1.DatabaseTarget_NetworkTarget{
			NetworkTarget: &remotequeriesv1alpha1.NetworkTarget{Host: "db-a1.internal", Port: port, Dbname: "orders"},
		},
	}
}

func remoteQueriesTargetWithDbname(dbname string) *remotequeriesv1alpha1.DatabaseTarget {
	return &remotequeriesv1alpha1.DatabaseTarget{
		Target: &remotequeriesv1alpha1.DatabaseTarget_NetworkTarget{
			NetworkTarget: &remotequeriesv1alpha1.NetworkTarget{Host: "db-a1.internal", Port: 5432, Dbname: dbname},
		},
	}
}

// TestHandleStartRun_FirstStartAccepted covers the first valid start for an
// identity.
func TestHandleStartRun_FirstStartAccepted(t *testing.T) {
	controller, clock := newRemoteQueriesTestController()

	req := remoteQueriesValidStartRunRequest()
	resp := startRun(t, controller, req)

	if got := resp.GetStatus(); got != remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_ACCEPTED {
		t.Errorf("expected ACCEPTED, got %s", got)
	}
	if resp.GetError() != nil {
		t.Errorf("expected no error detail, got %v", resp.GetError())
	}
	if !proto.Equal(resp.GetRunIdentity(), remoteQueriesTestRunIdentity()) {
		t.Errorf("expected the echoed run identity, got %v", resp.GetRunIdentity())
	}
	if want := timestamppb.New(clock.Now()); !proto.Equal(resp.GetAcceptedAt(), want) {
		t.Errorf("expected acceptance timestamp %v, got %v", want, resp.GetAcceptedAt())
	}
}

// TestHandleStartRun_IdenticalDuplicateAlreadyAccepted covers a duplicate
// start of the same identity and same canonical command.
func TestHandleStartRun_IdenticalDuplicateAlreadyAccepted(t *testing.T) {
	controller, clock := newRemoteQueriesTestController()

	first := startRun(t, controller, remoteQueriesValidStartRunRequest())
	clock.Advance(time.Minute)

	// A byte-identical redelivery reports the existing admission.
	duplicate := startRun(t, controller, remoteQueriesValidStartRunRequest())
	if got := duplicate.GetStatus(); got != remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_ALREADY_ACCEPTED {
		t.Errorf("expected ALREADY_ACCEPTED, got %s", got)
	}
	if !proto.Equal(duplicate.GetAcceptedAt(), first.GetAcceptedAt()) {
		t.Errorf("expected the ORIGINAL acceptance time %v, got %v", first.GetAcceptedAt(), duplicate.GetAcceptedAt())
	}

	// Transport and audit context are excluded from the canonical command,
	// so a duplicate under a different connection ID and reason is still the
	// same command.
	retitled := remoteQueriesValidStartRunRequest()
	retitled.ConnectionId = "conn-remote-queries-2"
	retitled.Reason = "redelivery after ambiguous timeout"
	again := startRun(t, controller, retitled)
	if got := again.GetStatus(); got != remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_ALREADY_ACCEPTED {
		t.Errorf("expected ALREADY_ACCEPTED with different connection_id/reason, got %s", got)
	}
	if !proto.Equal(again.GetAcceptedAt(), first.GetAcceptedAt()) {
		t.Errorf("expected the ORIGINAL acceptance time, got %v", again.GetAcceptedAt())
	}
}

// TestHandleStartRun_ConflictingDuplicateRejected covers the same identity
// with a different canonical command: it fails closed with the
// COMMAND_CONFLICT code.
func TestHandleStartRun_ConflictingDuplicateRejected(t *testing.T) {
	controller, _ := newRemoteQueriesTestController()

	startRun(t, controller, remoteQueriesValidStartRunRequest())

	t.Run("different query", func(t *testing.T) {
		req := remoteQueriesValidStartRunRequest()
		req.Query = "SELECT 1"
		resp := startRun(t, controller, req)
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED {
			t.Errorf("expected REJECTED, got %s", got)
		}
		if got := resp.GetError().GetCode(); got != remoteQueriesErrCommandConflict {
			t.Errorf("expected COMMAND_CONFLICT code, got %q", got)
		}
		if resp.GetAcceptedAt() != nil {
			t.Error("expected no acceptance timestamp on a rejected duplicate")
		}
	})

	t.Run("different integration", func(t *testing.T) {
		req := remoteQueriesValidStartRunRequest()
		req.Integration = "clickhouse"
		resp := startRun(t, controller, req)
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED {
			t.Errorf("expected REJECTED, got %s", got)
		}
	})

	t.Run("different target", func(t *testing.T) {
		req := remoteQueriesValidStartRunRequest()
		req.Target = &remotequeriesv1alpha1.DatabaseTarget{
			Target: &remotequeriesv1alpha1.DatabaseTarget_DatabaseInstance{DatabaseInstance: "orders-primary"},
		}
		resp := startRun(t, controller, req)
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED {
			t.Errorf("expected REJECTED, got %s", got)
		}
	})

	t.Run("different include_schema", func(t *testing.T) {
		req := remoteQueriesValidStartRunRequest()
		req.IncludeSchema = remoteQueriesBool(false)
		resp := startRun(t, controller, req)
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED {
			t.Errorf("expected REJECTED, got %s", got)
		}
	})

	t.Run("different limits", func(t *testing.T) {
		req := remoteQueriesValidStartRunRequest()
		req.ResultDelivery.Limits.TimeoutMs = 600000
		resp := startRun(t, controller, req)
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED {
			t.Errorf("expected REJECTED, got %s", got)
		}
		if got := resp.GetError().GetCode(); got != remoteQueriesErrCommandConflict {
			t.Errorf("expected COMMAND_CONFLICT code, got %q", got)
		}
	})

	t.Run("same command after cancellation", func(t *testing.T) {
		// The existing admission stays authoritative even once terminal:
		// the same command reports ALREADY_ACCEPTED rather than restarting.
		cancelRun(t, controller, newCancelRunRequest())
		resp := startRun(t, controller, remoteQueriesValidStartRunRequest())
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_ALREADY_ACCEPTED {
			t.Errorf("expected ALREADY_ACCEPTED after cancellation, got %s", got)
		}
	})
}

// TestHandleStartRun_InvalidRequestRejected covers structurally invalid
// start requests, which are rejected with per-field error codes.
func TestHandleStartRun_InvalidRequestRejected(t *testing.T) {
	controller, _ := newRemoteQueriesTestController()

	tests := map[string]func(*remotequeriesv1alpha1.StartRunRequest){
		"missing reason":            func(r *remotequeriesv1alpha1.StartRunRequest) { r.Reason = "" },
		"missing identity":          func(r *remotequeriesv1alpha1.StartRunRequest) { r.RunIdentity = nil },
		"zero org id":               func(r *remotequeriesv1alpha1.StartRunRequest) { r.RunIdentity.OrgId = 0 },
		"empty task id":             func(r *remotequeriesv1alpha1.StartRunRequest) { r.RunIdentity.TaskId = "" },
		"empty upload id":           func(r *remotequeriesv1alpha1.StartRunRequest) { r.RunIdentity.UploadId = "" },
		"empty integration":         func(r *remotequeriesv1alpha1.StartRunRequest) { r.Integration = "" },
		"missing target":            func(r *remotequeriesv1alpha1.StartRunRequest) { r.Target = nil },
		"empty query":               func(r *remotequeriesv1alpha1.StartRunRequest) { r.Query = " " },
		"missing result delivery":   func(r *remotequeriesv1alpha1.StartRunRequest) { r.ResultDelivery = nil },
		"zero artifact version":     func(r *remotequeriesv1alpha1.StartRunRequest) { r.ResultDelivery.ArtifactVersion = 0 },
		"negative artifact version": func(r *remotequeriesv1alpha1.StartRunRequest) { r.ResultDelivery.ArtifactVersion = -1 },
		"relative intake base url":  func(r *remotequeriesv1alpha1.StartRunRequest) { r.ResultDelivery.IntakeBaseUrl = "uploads" },
		"missing limits":            func(r *remotequeriesv1alpha1.StartRunRequest) { r.ResultDelivery.Limits = nil },
		"zero timeout_ms limit":     func(r *remotequeriesv1alpha1.StartRunRequest) { r.ResultDelivery.Limits.TimeoutMs = 0 },
		"zero max_file_bytes limit": func(r *remotequeriesv1alpha1.StartRunRequest) { r.ResultDelivery.Limits.MaxFileBytes = 0 },
	}
	for name, mutate := range tests {
		req := remoteQueriesValidStartRunRequest()
		mutate(req)
		resp := startRun(t, controller, req)
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED {
			t.Errorf("%s: expected REJECTED, got %s", name, got)
		}
		if resp.GetError().GetCode() == "" {
			t.Errorf("%s: expected a stable error code, got none", name)
		}
		if resp.GetAcceptedAt() != nil {
			t.Errorf("%s: expected no acceptance timestamp on a rejected request", name)
		}
	}
}

// TestHandleGetRunStatus covers the unknown and known status lookups,
// including that the response never fabricates receipts or diagnostics.
func TestHandleGetRunStatus(t *testing.T) {
	controller, clock := newRemoteQueriesTestController()

	t.Run("unknown identity", func(t *testing.T) {
		resp := getRunStatus(t, controller, newGetRunStatusRequest())
		if got := resp.GetState(); got != remotequeriesv1alpha1.RunState_RUN_STATE_NOT_FOUND {
			t.Errorf("expected NOT_FOUND, got %s", got)
		}
		if !proto.Equal(resp.GetRunIdentity(), remoteQueriesTestRunIdentity()) {
			t.Errorf("expected the echoed run identity, got %v", resp.GetRunIdentity())
		}
		if resp.GetUpdatedAt() != nil {
			t.Error("expected no update timestamp for an unknown identity")
		}
		if resp.GetError() != nil {
			t.Error("expected no fabricated terminal error")
		}
		if resp.GetReceipt() != nil {
			t.Error("expected no fabricated upload receipt")
		}
		if resp.GetDiagnostics() != nil {
			t.Error("expected no fabricated execution diagnostics")
		}
	})

	t.Run("known accepted identity", func(t *testing.T) {
		startRun(t, controller, remoteQueriesValidStartRunRequest())
		resp := getRunStatus(t, controller, newGetRunStatusRequest())
		if got := resp.GetState(); got != remotequeriesv1alpha1.RunState_RUN_STATE_ACCEPTED {
			t.Errorf("expected ACCEPTED, got %s", got)
		}
		if want := timestamppb.New(clock.Now()); !proto.Equal(resp.GetUpdatedAt(), want) {
			t.Errorf("expected update timestamp %v, got %v", want, resp.GetUpdatedAt())
		}
		if resp.GetReceipt() != nil {
			t.Error("expected no upload receipt for a run with no upload")
		}
		if resp.GetDiagnostics() != nil {
			t.Error("expected no execution diagnostics for a run with no execution")
		}
	})

	t.Run("cancelled identity", func(t *testing.T) {
		cancelRun(t, controller, newCancelRunRequest())
		resp := getRunStatus(t, controller, newGetRunStatusRequest())
		if got := resp.GetState(); got != remotequeriesv1alpha1.RunState_RUN_STATE_CANCELLED {
			t.Errorf("expected CANCELLED, got %s", got)
		}
	})
}

// TestHandleGetRunStatus_InvalidRequestSurfacesHandlerError covers the
// documented behavior that an invalid status lookup is returned as an error
// because RunState has no rejected value.
func TestHandleGetRunStatus_InvalidRequestSurfacesHandlerError(t *testing.T) {
	controller, _ := newRemoteQueriesTestController()

	reqs := map[string]*remotequeriesv1alpha1.GetRunStatusRequest{
		"missing reason":   {RunIdentity: remoteQueriesTestRunIdentity()},
		"missing identity": {Reason: "control-plane reference test"},
	}
	for name, req := range reqs {
		_, err := controller.handleGetRunStatus(1, marshalRemoteQueriesRequest(t, req))
		if err == nil {
			t.Errorf("%s: expected a handler error, got none", name)
		}
	}
}

// TestHandleCancelRun covers cancellation, repeated cancellation, terminal
// and not-found cases, and rejected invalid requests.
func TestHandleCancelRun(t *testing.T) {
	controller, clock := newRemoteQueriesTestController()

	t.Run("unknown identity", func(t *testing.T) {
		resp := cancelRun(t, controller, newCancelRunRequest())
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.CancelRunStatus_CANCEL_RUN_STATUS_NOT_FOUND {
			t.Errorf("expected NOT_FOUND, got %s", got)
		}
		if resp.GetUpdatedAt() != nil {
			t.Error("expected no update timestamp for an unknown identity")
		}
		if resp.GetError() != nil {
			t.Errorf("expected no error detail, got %v", resp.GetError())
		}
	})

	t.Run("cancel an accepted run", func(t *testing.T) {
		startRun(t, controller, remoteQueriesValidStartRunRequest())
		clock.Advance(time.Minute)

		resp := cancelRun(t, controller, newCancelRunRequest())
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.CancelRunStatus_CANCEL_RUN_STATUS_CANCELLATION_REQUESTED {
			t.Errorf("expected CANCELLATION_REQUESTED, got %s", got)
		}
		if want := timestamppb.New(clock.Now()); !proto.Equal(resp.GetUpdatedAt(), want) {
			t.Errorf("expected update timestamp %v, got %v", want, resp.GetUpdatedAt())
		}

		// The no-work simulation transitions the entry directly to
		// CANCELLED, observable via GetRunStatus.
		status := getRunStatus(t, controller, newGetRunStatusRequest())
		if got := status.GetState(); got != remotequeriesv1alpha1.RunState_RUN_STATE_CANCELLED {
			t.Errorf("expected CANCELLED after cancellation, got %s", got)
		}
	})

	t.Run("repeated cancellation", func(t *testing.T) {
		resp := cancelRun(t, controller, newCancelRunRequest())
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.CancelRunStatus_CANCEL_RUN_STATUS_ALREADY_TERMINAL {
			t.Errorf("expected deterministic ALREADY_TERMINAL for a cancelled run, got %s", got)
		}
		if resp.GetUpdatedAt() == nil {
			t.Error("expected the terminal update timestamp for a known terminal run")
		}
	})

	t.Run("invalid request", func(t *testing.T) {
		req := newCancelRunRequest()
		req.Reason = ""
		resp := cancelRun(t, controller, req)
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.CancelRunStatus_CANCEL_RUN_STATUS_REJECTED {
			t.Errorf("expected REJECTED, got %s", got)
		}
		if got := resp.GetError().GetCode(); got != remoteQueriesErrMissingReason {
			t.Errorf("expected MISSING_REASON code, got %q", got)
		}
	})
}

// TestRemoteQueriesHandlers_MalformedProtobuf covers the shared decode path
// for every handler: malformed input returns an error rather than panicking,
// and an empty payload decodes as a zero message and is rejected without
// panicking.
func TestRemoteQueriesHandlers_MalformedProtobuf(t *testing.T) {
	controller, _ := newRemoteQueriesTestController()

	handlers := map[string]func(uint64, []byte) ([]byte, error){
		"ResolveTarget": controller.handleResolveTarget,
		"StartRun":      controller.handleStartRun,
		"GetRunStatus":  controller.handleGetRunStatus,
		"CancelRun":     controller.handleCancelRun,
	}
	// A lone 0xff varint is an invalid tag; 0x0a 0x05 declares a 5-byte
	// field 1 that never arrives; 0x08 0xff declares a truncated varint
	// value for field 1.
	malformedPayloads := [][]byte{{0xff}, {0x0a, 0x05, 0x01}, {0x08, 0xff}}

	for name, handler := range handlers {
		for i, payload := range malformedPayloads {
			if _, err := handler(1, payload); err == nil {
				t.Errorf("%s: malformed payload %d: expected an error, got none", name, i)
			}
		}
		// An empty payload decodes to a zero message; every handler must
		// reject it deterministically without panicking.
		raw, err := handler(1, nil)
		if err != nil {
			// GetRunStatus has no rejected state, so it surfaces a handler
			// error; that is the documented behavior for this method.
			if name != "GetRunStatus" {
				t.Errorf("%s: empty payload: unexpected handler error: %v", name, err)
			}
			continue
		}
		switch name {
		case "ResolveTarget":
			var resp remotequeriesv1alpha1.ResolveTargetResponse
			if err := proto.Unmarshal(raw, &resp); err != nil {
				t.Fatalf("%s: unmarshal response: %v", name, err)
			}
			if got := resp.GetStatus(); got != remotequeriesv1alpha1.ResolveTargetStatus_RESOLVE_TARGET_STATUS_RESOLUTION_ERROR {
				t.Errorf("%s: empty payload: expected RESOLUTION_ERROR, got %s", name, got)
			}
		case "StartRun":
			var resp remotequeriesv1alpha1.StartRunResponse
			if err := proto.Unmarshal(raw, &resp); err != nil {
				t.Fatalf("%s: unmarshal response: %v", name, err)
			}
			if got := resp.GetStatus(); got != remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED {
				t.Errorf("%s: empty payload: expected REJECTED, got %s", name, got)
			}
		case "CancelRun":
			var resp remotequeriesv1alpha1.CancelRunResponse
			if err := proto.Unmarshal(raw, &resp); err != nil {
				t.Fatalf("%s: unmarshal response: %v", name, err)
			}
			if got := resp.GetStatus(); got != remotequeriesv1alpha1.CancelRunStatus_CANCEL_RUN_STATUS_REJECTED {
				t.Errorf("%s: empty payload: expected REJECTED, got %s", name, got)
			}
		}
	}
}

// TestCanonicalCommandDigest covers the deterministic digest directly: it
// must ignore transport/audit/observability fields (connection_id, reason,
// trace context) and the deduplication key (the run identity), while
// detecting every change to the command's execution semantics.
func TestCanonicalCommandDigest(t *testing.T) {
	base := remoteQueriesValidStartRunRequest()
	want := canonicalCommandDigest(base)

	if got := canonicalCommandDigest(remoteQueriesValidStartRunRequest()); got != want {
		t.Error("expected the digest to be deterministic across calls")
	}

	unchanged := []struct {
		name string
		keep func(req *remotequeriesv1alpha1.StartRunRequest)
	}{
		{"different connection_id", func(r *remotequeriesv1alpha1.StartRunRequest) { r.ConnectionId = "conn-remote-queries-2" }},
		{"different reason", func(r *remotequeriesv1alpha1.StartRunRequest) { r.Reason = "an unrelated audit reason" }},
		{"different trace context", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.TraceContext = &remotequeriesv1alpha1.TraceContext{TraceId: 1234, ParentId: 5678, SamplingPriority: 1}
		}},
	}
	for _, tc := range unchanged {
		req := remoteQueriesValidStartRunRequest()
		tc.keep(req)
		if got := canonicalCommandDigest(req); got != want {
			t.Errorf("%s: digest must not change: got %s, want %s", tc.name, got, want)
		}
	}

	// An unset include_schema and an explicit false carry identical execution
	// semantics (both disable the schema), so their digests must match.
	unsetInclude := remoteQueriesValidStartRunRequest()
	unsetInclude.IncludeSchema = nil
	explicitFalse := remoteQueriesValidStartRunRequest()
	explicitFalse.IncludeSchema = remoteQueriesBool(false)
	if got, other := canonicalCommandDigest(unsetInclude), canonicalCommandDigest(explicitFalse); got != other {
		t.Errorf("expected unset and explicit-false include_schema to share a digest, got %s and %s", got, other)
	}

	changed := []struct {
		name string
		mut  func(req *remotequeriesv1alpha1.StartRunRequest)
	}{
		{"different query", func(r *remotequeriesv1alpha1.StartRunRequest) { r.Query = "SELECT 1" }},
		{"different integration", func(r *remotequeriesv1alpha1.StartRunRequest) { r.Integration = "clickhouse" }},
		{"different host", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.Target.GetNetworkTarget().Host = "db-a2.internal"
		}},
		{"different port", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.Target.GetNetworkTarget().Port = 5433
		}},
		{"different target kind", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.Target = &remotequeriesv1alpha1.DatabaseTarget{
				Target: &remotequeriesv1alpha1.DatabaseTarget_DatabaseInstance{DatabaseInstance: "orders-primary"},
			}
		}},
		{"explicit false include_schema", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.IncludeSchema = &[]bool{false}[0]
		}},
		{"different artifact version", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.ResultDelivery.ArtifactVersion = 2
		}},
		{"different intake base url", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.ResultDelivery.IntakeBaseUrl = "https://intake-2.example.internal"
		}},
		{"different max_file_bytes", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.ResultDelivery.Limits.MaxFileBytes = 64 * 1024 * 1024
		}},
		{"different max_result_bytes", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.ResultDelivery.Limits.MaxResultBytes = 42
		}},
		{"different max_row_bytes", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.ResultDelivery.Limits.MaxRowBytes = 42
		}},
		{"different max_columns", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.ResultDelivery.Limits.MaxColumns = 42
		}},
		{"different max_schema_bytes", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.ResultDelivery.Limits.MaxSchemaBytes = 42
		}},
		{"different max_pages", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.ResultDelivery.Limits.MaxPages = 42
		}},
		{"different timeout_ms", func(r *remotequeriesv1alpha1.StartRunRequest) {
			r.ResultDelivery.Limits.TimeoutMs = 42
		}},
	}
	for _, tc := range changed {
		req := remoteQueriesValidStartRunRequest()
		tc.mut(req)
		if got := canonicalCommandDigest(req); got == want {
			t.Errorf("%s: digest must change with the command's execution semantics", tc.name)
		}
	}

	// The digest must also distinguish values whose plain concatenation
	// would collide without the length prefixes.
	a := remoteQueriesValidStartRunRequest()
	a.Integration = "ab"
	a.Query = "c"
	b := remoteQueriesValidStartRunRequest()
	b.Integration = "a"
	b.Query = "bc"
	if canonicalCommandDigest(a) == canonicalCommandDigest(b) {
		t.Error("expected the length-prefixed encoding to distinguish field boundaries")
	}
}

// TestHandleStartRun_ConcurrentDuplicates proves the controller is
// concurrency-safe: concurrent duplicates of one identity and command admit
// exactly once, and concurrent cancellations of one admitted run produce a
// deterministic one-request/one-already-terminal split.
func TestHandleStartRun_ConcurrentDuplicates(t *testing.T) {
	const goroutines = 32

	controller, _ := newRemoteQueriesTestController()

	var wg sync.WaitGroup
	results := make([]*remotequeriesv1alpha1.StartRunResponse, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := remoteQueriesValidStartRunRequest()
			req.ConnectionId = fmt.Sprintf("conn-remote-queries-%d", i)
			req.Reason = fmt.Sprintf("concurrent duplicate %d", i)
			results[i] = startRun(t, controller, req)
		}(i)
	}
	wg.Wait()

	accepted, already := 0, 0
	for _, resp := range results {
		switch resp.GetStatus() {
		case remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_ACCEPTED:
			accepted++
		case remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_ALREADY_ACCEPTED:
			already++
		default:
			t.Fatalf("unexpected concurrent start status %s", resp.GetStatus())
		}
	}
	if accepted != 1 || already != goroutines-1 {
		t.Errorf("expected exactly one ACCEPTED and %d ALREADY_ACCEPTED, got %d/%d", goroutines-1, accepted, already)
	}
	firstAcceptedAt := results[0].GetAcceptedAt()
	for _, resp := range results[1:] {
		if !proto.Equal(resp.GetAcceptedAt(), firstAcceptedAt) {
			t.Error("expected all duplicates to report the original acceptance time")
		}
	}

	// Concurrent cancellations of the admitted run: exactly one
	// CANCELLATION_REQUESTED, the rest ALREADY_TERMINAL.
	cancelResults := make([]*remotequeriesv1alpha1.CancelRunResponse, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cancelResults[i] = cancelRun(t, controller, newCancelRunRequest())
		}(i)
	}
	wg.Wait()

	requested, alreadyTerminal := 0, 0
	for _, resp := range cancelResults {
		switch resp.GetStatus() {
		case remotequeriesv1alpha1.CancelRunStatus_CANCEL_RUN_STATUS_CANCELLATION_REQUESTED:
			requested++
		case remotequeriesv1alpha1.CancelRunStatus_CANCEL_RUN_STATUS_ALREADY_TERMINAL:
			alreadyTerminal++
		default:
			t.Fatalf("unexpected concurrent cancel status %s", resp.GetStatus())
		}
	}
	if requested != 1 || alreadyTerminal != goroutines-1 {
		t.Errorf("expected exactly one CANCELLATION_REQUESTED and %d ALREADY_TERMINAL, got %d/%d", goroutines-1, requested, alreadyTerminal)
	}
}
