package main

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	remotequeriesv1alpha1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_queries"
)

// callHandler marshals req, invokes h, and unmarshals the response into resp.
func callHandler(t *testing.T, h func(context.Context, uint64, []byte) ([]byte, error), req, resp proto.Message) {
	t.Helper()
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	respBytes, err := h(context.Background(), 1, payload)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if err := proto.Unmarshal(respBytes, resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
}

func TestHandleStartRun(t *testing.T) {
	var resp remotequeriesv1alpha1.StartRunResponse
	callHandler(t, handleStartRun, &remotequeriesv1alpha1.StartRunRequest{
		ConnectionId: "conn-123",
		Reason:       "integration test",
		Integration:  "postgres",
	}, &resp)
	if got, want := resp.GetStatus(), remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED; got != want {
		t.Fatalf("status = %v, want %v", got, want)
	}
}

func TestHandleResolveTarget(t *testing.T) {
	var resp remotequeriesv1alpha1.ResolveTargetResponse
	callHandler(t, handleResolveTarget, &remotequeriesv1alpha1.ResolveTargetRequest{
		ConnectionId: "conn-123",
		Reason:       "integration test",
		Integration:  "postgres",
	}, &resp)
	if got, want := resp.GetStatus(), remotequeriesv1alpha1.ResolveTargetStatus_RESOLVE_TARGET_STATUS_TARGET_NOT_FOUND; got != want {
		t.Fatalf("status = %v, want %v", got, want)
	}
}
