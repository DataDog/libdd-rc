package main

import (
	"testing"

	remotequeriesv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_queries"
	"google.golang.org/protobuf/proto"
)

func TestHandleRemoteQueryPing(t *testing.T) {
	const reason = "remote queries smoke test"

	req := &remotequeriesv1.PingRequest{
		ConnectionId: "conn-456",
		Reason:       reason,
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	respBytes, err := handleRemoteQueryPing(1, payload)
	if err != nil {
		t.Fatalf("handleRemoteQueryPing returned error: %v", err)
	}

	var resp remotequeriesv1.PingResponse
	if err := proto.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.GetNow() == nil {
		t.Fatal("expected pong response to carry a timestamp")
	}

	if got := resp.GetReason(); got != reason {
		t.Fatalf("expected pong response to echo reason %q, got %q", reason, got)
	}
}
