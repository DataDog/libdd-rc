package main

import (
	"log"

	remotequeriesv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_queries"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// handleRemoteQueryPing implements libddrcffi.HandlerFunc for the
// RemoteQueryService/Ping uri. It answers a PingRequest with a PingResponse
// carrying the current time and echoing back the request's reason.
func handleRemoteQueryPing(correlationID uint64, payload []byte) ([]byte, error) {
	var req remotequeriesv1.PingRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return nil, err
	}

	log.Printf("received remote query ping (correlation_id=%d) from connection %q: reason=%q", correlationID, req.GetConnectionId(), req.GetReason())

	resp := &remotequeriesv1.PingResponse{
		Now:    timestamppb.Now(),
		Reason: req.GetReason(),
	}
	return proto.Marshal(resp)
}
