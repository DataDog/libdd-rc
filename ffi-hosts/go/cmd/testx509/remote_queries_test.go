package main

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	remotequeriesv1alpha1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_queries"
)

func TestHandleExecute(t *testing.T) {
	for _, tt := range []struct {
		resolveOnly bool
		wantCode    string
	}{
		{resolveOnly: false, wantCode: "EXECUTION_UNAVAILABLE"},
		{resolveOnly: true, wantCode: "TARGET_NOT_FOUND"},
	} {
		payload, err := proto.Marshal(&remotequeriesv1alpha1.ExecuteRequest{ResolveOnly: tt.resolveOnly})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		respBytes, err := handleExecute(context.Background(), 1, payload)
		if err != nil {
			t.Fatalf("handler returned error: %v", err)
		}
		var resp remotequeriesv1alpha1.ExecuteResponse
		if err := proto.Unmarshal(respBytes, &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if got := resp.GetStatus(); got != remotequeriesv1alpha1.ExecuteStatus_EXECUTE_STATUS_REJECTED {
			t.Fatalf("status = %s, want REJECTED", got)
		}
		if got := resp.GetErrorCode(); got != tt.wantCode {
			t.Fatalf("error_code = %q, want %q", got, tt.wantCode)
		}
	}
}
