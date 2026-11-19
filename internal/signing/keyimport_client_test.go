// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

type oldImportPeer struct {
	signerpb.SignerServiceClient
	legacyCalls int
}

func (p *oldImportPeer) PrepareKeyImport(context.Context, *signerpb.PrepareKeyImportRequest, ...grpc.CallOption) (*signerpb.PrepareKeyImportResponse, error) {
	p.legacyCalls++
	return &signerpb.PrepareKeyImportResponse{}, nil
}

func (p *oldImportPeer) ImportWrappedKey(context.Context, *signerpb.ImportWrappedKeyRequest, ...grpc.CallOption) (*signerpb.ImportWrappedKeyResponse, error) {
	p.legacyCalls++
	return &signerpb.ImportWrappedKeyResponse{}, nil
}

func (p *oldImportPeer) PrepareKeyImportV2(context.Context, *signerpb.PrepareKeyImportV2Request, ...grpc.CallOption) (*signerpb.PrepareKeyImportV2Response, error) {
	return nil, status.Error(codes.Unimplemented, "unknown method PrepareKeyImportV2")
}

func (p *oldImportPeer) ImportWrappedKeyV2(context.Context, *signerpb.ImportWrappedKeyV2Request, ...grpc.CallOption) (*signerpb.ImportWrappedKeyV2Response, error) {
	return nil, status.Error(codes.Unimplemented, "unknown method ImportWrappedKeyV2")
}

func TestImportClientRequiresNewSignerWithoutFallback(t *testing.T) {
	f := newImportRecoveryFixture(t)
	peer := &oldImportPeer{}
	client := &Client{svc: peer}
	if _, err := client.PrepareKeyImport(t.Context(), f.policy); status.Code(err) != codes.Unimplemented {
		t.Fatalf("preparing on an old signer returned %v, want Unimplemented", err)
	}
	if result, err := client.ImportDualControlKey(t.Context(), KeyImport{Policy: f.policy, SealedKey: []byte("test ciphertext")}, PurposeCASign, f.authorizer); result != nil || status.Code(err) != codes.Unimplemented {
		t.Fatalf("importing on an old signer returned %v, want Unimplemented", err)
	}
	if peer.legacyCalls != 0 {
		t.Fatalf("v2 client called the old protocol %d times", peer.legacyCalls)
	}
}
