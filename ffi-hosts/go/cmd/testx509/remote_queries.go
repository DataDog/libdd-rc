package main

import (
	"context"
	"log"

	"google.golang.org/protobuf/proto"

	remotequeriesv1alpha1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_queries"
)

// handleExecute implements libddrcffi.HandlerFunc for the
// RemoteQueriesService/Execute uri. It rejects every request.
func handleExecute(_ context.Context, correlationID uint64, payload []byte) ([]byte, error) {
	var req remotequeriesv1alpha1.ExecuteRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return nil, err
	}

	log.Printf("==> received EXECUTE (correlation_id=%d) from connection %q: run_id=%q integration=%q resolve_only=%v",
		correlationID, req.GetConnectionId(), req.GetResultDelivery().GetRunId(), req.GetIntegration(), req.GetResolveOnly())

	code := "EXECUTION_UNAVAILABLE"
	if req.GetResolveOnly() {
		code = "TARGET_NOT_FOUND"
	}

	return proto.Marshal(&remotequeriesv1alpha1.ExecuteResponse{
		Status:       remotequeriesv1alpha1.ExecuteStatus_EXECUTE_STATUS_REJECTED,
		ErrorCode:    code,
		ErrorMessage: "testx509 does not execute queries",
	})
}
