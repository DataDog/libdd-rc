package main

import (
	"bytes"
	"context"
	"log"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	rcsecretsv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel/remote_config/rc_secrets"
)

// handlePrepareSecretDelivery implements libddrcffi.HandlerFunc for the
// SecretsService/PrepareSecretDelivery uri. It answers a
// PrepareSecretDeliveryRequest with stub values.
func handlePrepareSecretDelivery(_ context.Context, correlationID uint64, payload []byte) ([]byte, error) {
	var req rcsecretsv1.PrepareSecretDeliveryRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		return nil, err
	}

	log.Printf("==> received PrepareSecretDelivery")
	log.Printf("      (correlation_id=%d) from connection %q: encryption_context_id=%q product=%q",
		correlationID, req.GetConnectionId(), req.GetEncryptionContextId(), req.GetProduct())

	resp := &rcsecretsv1.PrepareSecretDeliveryResponse{
		Status:      rcsecretsv1.PrepareSecretDeliveryStatus_PREPARE_SECRET_DELIVERY_STATUS_OK,
		Token:       "stub-token",
		PublicKey:   bytes.Repeat([]byte{0x01}, 32),
		KeyType:     rcsecretsv1.KeyType_KEY_TYPE_NACL_SEALED_BOX_X25519,
		KeyValidity: durationpb.New(60 * time.Second),
	}
	return proto.Marshal(resp)
}
