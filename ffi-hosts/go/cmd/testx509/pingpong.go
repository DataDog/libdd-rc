package main

import (
	"context"
	"log"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	remoteconfigv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_config"
)

// handlePing implements libddrcffi.HandlerFunc for the
// DebugService/Ping uri. It answers a PingRequest with a PingResponse
// carrying the current time.
func handlePing(_ context.Context, correlationID uint64, payload []byte) ([]byte, error) {
	var req remoteconfigv1.PingRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return nil, err
	}

	log.Printf("")
	log.Printf("")
	log.Printf("==> received PING")
	log.Printf("      (correlation_id=%d) from connection %q: reason=%q", correlationID, req.GetConnectionId(), req.GetReason())
	log.Printf("")
	log.Printf("")

	resp := &remoteconfigv1.PingResponse{
		Now: timestamppb.Now(),
	}
	return proto.Marshal(resp)
}
