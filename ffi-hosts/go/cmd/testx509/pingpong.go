package main

import (
	"errors"
	"log"

	remoteconfigv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_config"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// errUnsupportedSubtopic is returned by handleDebugService when a
// DebugServiceRequest carries a subtopic this example does not implement.
var errUnsupportedSubtopic = errors.New("testx509: unsupported DebugServiceRequest subtopic")

// handleDebugService implements libddrcffi.HandlerFunc for the
// NAMESPACE_REMOTE_CONFIG namespace. It answers a Ping subtopic with a Pong
// carrying the current time.
func handleDebugService(correlationID uint64, payload []byte) ([]byte, error) {
	var req remoteconfigv1.DebugServiceRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return nil, err
	}

	switch subtopic := req.GetSubtopic().(type) {
	case *remoteconfigv1.DebugServiceRequest_Ping:
		ping := subtopic.Ping
		log.Printf("received ping (correlation_id=%d) from connection %q: reason=%q", correlationID, ping.GetConnectionId(), ping.GetReason())

		resp := &remoteconfigv1.DebugServiceResponse{
			Subtopic: &remoteconfigv1.DebugServiceResponse_Ping{
				Ping: &remoteconfigv1.PingResponse{
					Now: timestamppb.Now(),
				},
			},
		}
		return proto.Marshal(resp)
	default:
		return nil, errUnsupportedSubtopic
	}
}
