// SPDX-License-Identifier: MPL-2.0

package signing

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/grpc"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

type capturingManagedKeyRPC struct {
	signerpb.SignerServiceClient
	request    *signerpb.SignManagedKeyRequest
	tokenAtRPC []byte
}

func (c *capturingManagedKeyRPC) SignManagedKey(_ context.Context, request *signerpb.SignManagedKeyRequest, _ ...grpc.CallOption) (*signerpb.SignManagedKeyResponse, error) {
	c.request = request
	c.tokenAtRPC = bytes.Clone(request.GetAuthorizationToken())
	return &signerpb.SignManagedKeyResponse{Signature: []byte{0x30, 0x00}}, nil
}

type fixedManagedKeyTokenProvider struct{ token []byte }

func (p fixedManagedKeyTokenProvider) Authorize(crypto.SignIntent) ([]byte, error) {
	return bytes.Clone(p.token), nil
}

func TestManagedKeyClientWipesProtobufAuthorizationTokenAfterRPC(t *testing.T) {
	rpc := &capturingManagedKeyRPC{}
	client := &Client{svc: rpc}
	signer, err := client.SignerForManagedKey(
		"tenant-a", "aws-kms", "key-ref", crypto.RSA2048, []byte{0x30, 0x00},
		PurposeCASign, fixedManagedKeyTokenProvider{token: bytes.Repeat([]byte{0xA5}, 32)},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.SignDigest(bytes.Repeat([]byte{0x11}, 32), crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15}); err != nil {
		t.Fatal(err)
	}
	if len(rpc.tokenAtRPC) == 0 || bytes.Equal(rpc.tokenAtRPC, make([]byte, len(rpc.tokenAtRPC))) {
		t.Fatal("RPC did not receive the authorization token before wipe")
	}
	if rpc.request == nil || len(rpc.request.AuthorizationToken) == 0 {
		t.Fatal("captured protobuf request/token is missing")
	}
	for index, value := range rpc.request.AuthorizationToken {
		if value != 0 {
			t.Fatalf("protobuf authorization token byte %d was not wiped", index)
		}
	}
}
