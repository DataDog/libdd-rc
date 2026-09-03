package main

import (
	"errors"
	"testing"

	remoteconfigv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_config"
	"google.golang.org/protobuf/proto"
)

func TestHandleDebugService_Ping(t *testing.T) {
	req := &remoteconfigv1.DebugServiceRequest{
		Subtopic: &remoteconfigv1.DebugServiceRequest_Ping{
			Ping: &remoteconfigv1.PingRequest{
				ConnectionId: "conn-123",
				Reason:       "integration test",
			},
		},
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	respBytes, err := handleDebugService(1, payload)
	if err != nil {
		t.Fatalf("handleDebugService returned error: %v", err)
	}

	var resp remoteconfigv1.DebugServiceResponse
	if err := proto.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	pong := resp.GetPing()
	if pong == nil {
		t.Fatal("expected a ping subtopic in the response")
	}
	if pong.GetNow() == nil {
		t.Fatal("expected pong response to carry a timestamp")
	}
}

func TestHandleDebugService_UnsetSubtopic(t *testing.T) {
	req := &remoteconfigv1.DebugServiceRequest{}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	_, err = handleDebugService(1, payload)
	if !errors.Is(err, errUnsupportedSubtopic) {
		t.Fatalf("expected errUnsupportedSubtopic, got %v", err)
	}
}
