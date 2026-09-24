package main

import (
	"context"
	"log"

	"google.golang.org/protobuf/proto"

	remotequeriesv1alpha1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_queries"
)

// handleStartRun implements libddrcffi.HandlerFunc for the
// RemoteQueriesService/StartRun uri. It logs the request and responds REJECTED
// with TARGET_NOT_FOUND when resolve_only is set, else EXECUTION_UNAVAILABLE.
func handleStartRun(_ context.Context, correlationID uint64, payload []byte) ([]byte, error) {
	var req remotequeriesv1alpha1.StartRunRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return nil, err
	}

	log.Printf("==> received START_RUN (correlation_id=%d) from connection %q: reason=%q run_id=%q integration=%q resolve_only=%v",
		correlationID, req.GetConnectionId(), req.GetReason(), req.GetResultDelivery().GetRunId(), req.GetIntegration(), req.GetResolveOnly())

	code := "EXECUTION_UNAVAILABLE"
	if req.GetResolveOnly() {
		code = "TARGET_NOT_FOUND"
	}

	return proto.Marshal(&remotequeriesv1alpha1.StartRunResponse{
		Status:       remotequeriesv1alpha1.StartRunStatus_START_RUN_STATUS_REJECTED,
		ErrorCode:    code,
		ErrorMessage: "testx509 does not execute queries",
	})
}
