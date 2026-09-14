package main

import (
	"testing"

	remoteconfigv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_config"
	"google.golang.org/protobuf/proto"
)

func TestHandlePing(t *testing.T) {
	req := &remoteconfigv1.PingRequest{
		ConnectionId: "conn-123",
		Reason:       "integration test",
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	respBytes, err := handlePing(1, payload)
	if err != nil {
		t.Fatalf("handlePing returned error: %v", err)
	}

	var resp remoteconfigv1.PingResponse
	if err := proto.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.GetNow() == nil {
		t.Fatal("expected pong response to carry a timestamp")
	}
}
