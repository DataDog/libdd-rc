package main

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	rcsecretsv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_config/rc_secrets"
)

func TestHandlePrepareSecretDelivery(t *testing.T) {
	req := &rcsecretsv1.PrepareSecretDeliveryRequest{
		ConnectionId:        "conn-123",
		EncryptionContextId: "ctx-456",
		Product:             "ndm",
	}
	payload, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	respBytes, err := handlePrepareSecretDelivery(context.Background(), 1, payload)
	if err != nil {
		t.Fatalf("handlePrepareSecretDelivery returned error: %v", err)
	}

	var resp rcsecretsv1.PrepareSecretDeliveryResponse
	if err := proto.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if got, want := resp.GetStatus(), rcsecretsv1.PrepareSecretDeliveryStatus_PREPARE_SECRET_DELIVERY_STATUS_OK; got != want {
		t.Errorf("status = %v, want %v", got, want)
	}
	if resp.GetToken() == "" {
		t.Error("expected response to carry a token")
	}
	if got := len(resp.GetPublicKey()); got != 32 {
		t.Errorf("public key length = %d, want 32", got)
	}
	if got, want := resp.GetKeyType(), rcsecretsv1.KeyType_KEY_TYPE_NACL_SEALED_BOX_X25519; got != want {
		t.Errorf("key type = %v, want %v", got, want)
	}
	if resp.GetKeyValidity().AsDuration() <= time.Duration(0) {
		t.Errorf("key validity = %v, want positive", resp.GetKeyValidity().AsDuration())
	}
}

func TestHandlePrepareSecretDeliveryInvalidPayload(t *testing.T) {
	// A truncated length-delimited field is not valid protobuf.
	if _, err := handlePrepareSecretDelivery(context.Background(), 1, []byte{0x0a, 0xff}); err == nil {
		t.Fatal("expected an error for a malformed payload")
	}
}
