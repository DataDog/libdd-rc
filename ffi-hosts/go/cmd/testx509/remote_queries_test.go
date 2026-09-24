package main

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	remotequeriesv1alpha1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_queries"
)

func TestHandleStartRun(t *testing.T) {
	req := &remotequeriesv1alpha1.StartRunRequest{
		ConnectionId: "conn-123",
		Reason:       "integration test",
		Integration:  "postgres",
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	respBytes, err := handleStartRun(context.Background(), 1, payload)
	if err != nil {
		t.Fatalf("handleStartRun returned error: %v", err)
	}
	var resp remotequeriesv1alpha1.StartRunResponse
	if err := proto.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if got, want := resp.GetStatus(), remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED; got != want {
		t.Fatalf("status = %v, want %v", got, want)
	}
	if got, want := resp.GetErrorCode(), "EXECUTION_UNAVAILABLE"; got != want {
		t.Fatalf("error_code = %q, want %q", got, want)
	}
}

func TestHandleCancelRun(t *testing.T) {
	req := &remotequeriesv1alpha1.CancelRunRequest{
		ConnectionId: "conn-123",
		Reason:       "integration test",
		RunId:        "run-456",
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	respBytes, err := handleCancelRun(context.Background(), 1, payload)
	if err != nil {
		t.Fatalf("handleCancelRun returned error: %v", err)
	}
	var resp remotequeriesv1alpha1.CancelRunResponse
	if err := proto.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if got, want := resp.GetStatus(), remotequeriesv1alpha1.CancelRunStatus_CANCEL_RUN_STATUS_NOT_RUNNING; got != want {
		t.Fatalf("status = %v, want %v", got, want)
	}
}
