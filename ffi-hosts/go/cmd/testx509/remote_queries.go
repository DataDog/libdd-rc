package main

import (
	"context"
	"log"

	"google.golang.org/protobuf/proto"

	remotequeriesv1alpha1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_queries"
)

// handleStartRun implements libddrcffi.HandlerFunc for the
// RemoteQueriesService/StartRun uri. It logs the request and responds REJECTED.
func handleStartRun(_ context.Context, correlationID uint64, payload []byte) ([]byte, error) {
	var req remotequeriesv1alpha1.StartRunRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return nil, err
	}

	log.Printf("==> received START_RUN (correlation_id=%d) from connection %q: reason=%q run_id=%q integration=%q",
		correlationID, req.GetConnectionId(), req.GetReason(), req.GetResultDelivery().GetRunId(), req.GetIntegration())

	resp := &remotequeriesv1alpha1.StartRunResponse{
		Status:       remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED,
		ErrorCode:    "EXECUTION_UNAVAILABLE",
		ErrorMessage: "testx509 does not execute queries",
	}
	return proto.Marshal(resp)
}

// handleCancelRun implements libddrcffi.HandlerFunc for the
// RemoteQueriesService/CancelRun uri. It logs the request and responds NOT_RUNNING.
func handleCancelRun(_ context.Context, correlationID uint64, payload []byte) ([]byte, error) {
	var req remotequeriesv1alpha1.CancelRunRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return nil, err
	}

	log.Printf("==> received CANCEL_RUN (correlation_id=%d) from connection %q: reason=%q run_id=%q",
		correlationID, req.GetConnectionId(), req.GetReason(), req.GetRunId())

	resp := &remotequeriesv1alpha1.CancelRunResponse{
		Status: remotequeriesv1alpha1.CancelRunStatus_CANCEL_RUN_STATUS_NOT_RUNNING,
	}
	return proto.Marshal(resp)
}
