package main

import (
	"context"
	"log"

	"google.golang.org/protobuf/proto"

	remotequeriesv1alpha1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_queries"
)

// handleResolveTarget implements libddrcffi.HandlerFunc for the
// RemoteQueriesService/ResolveTarget uri. It logs the request and responds
// TARGET_NOT_FOUND.
func handleResolveTarget(_ context.Context, correlationID uint64, payload []byte) ([]byte, error) {
	var req remotequeriesv1alpha1.ResolveTargetRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return nil, err
	}

	log.Printf("==> received RESOLVE_TARGET (correlation_id=%d) from connection %q: reason=%q integration=%q",
		correlationID, req.GetConnectionId(), req.GetReason(), req.GetIntegration())

	return proto.Marshal(&remotequeriesv1alpha1.ResolveTargetResponse{
		Status: remotequeriesv1alpha1.ResolveTargetStatus_RESOLVE_TARGET_STATUS_TARGET_NOT_FOUND,
	})
}

// handleStartRun implements libddrcffi.HandlerFunc for the
// RemoteQueriesService/StartRun uri. It logs the request and responds REJECTED.
func handleStartRun(_ context.Context, correlationID uint64, payload []byte) ([]byte, error) {
	var req remotequeriesv1alpha1.StartRunRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return nil, err
	}

	log.Printf("==> received START_RUN (correlation_id=%d) from connection %q: reason=%q run_id=%q integration=%q",
		correlationID, req.GetConnectionId(), req.GetReason(), req.GetResultDelivery().GetRunId(), req.GetIntegration())

	return proto.Marshal(&remotequeriesv1alpha1.StartRunResponse{
		Status:       remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED,
		ErrorCode:    "EXECUTION_UNAVAILABLE",
		ErrorMessage: "testx509 does not execute queries",
	})
}
