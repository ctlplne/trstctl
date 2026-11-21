// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func TestCR184RevokedAuditKeyCannotSignArtifact(t *testing.T) {
	ctx := t.Context()
	srv := signing.NewServer()
	defer srv.Shutdown()
	const handle = "audit-export"
	if _, err := srv.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm:       signerpb.Algorithm_ALGORITHM_RSA_2048,
		RequestedId:     handle,
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_AUDIT_EVIDENCE},
	}); err != nil {
		t.Fatal(err)
	}
	req := &signerpb.SignArtifactRequest{
		Kind: jose.ArtifactAuditExport, TenantId: "deployment",
		AuthorityId: "audit-evidence", KeyId: handle,
		Payload: []byte(`{"format":"trstctl.audit-export.v1"}`),
	}
	if _, err := srv.SignArtifact(ctx, req); err != nil {
		t.Fatalf("audit key did not sign before revocation: %v", err)
	}
	if _, err := srv.RevokeKey(ctx, &signerpb.RevokeKeyRequest{
		Handle: &signerpb.KeyHandle{Id: handle}, OperationId: "revoke-audit", Reason: "key_compromise",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.SignArtifact(ctx, req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("revoked audit key signed artifact: %v", err)
	}
}

func TestCR184CachedCustodySignerRefusesRevokedKey(t *testing.T) {
	ctx := context.Background()
	srv := signing.NewServer()
	defer srv.Shutdown()
	const handle = "agid-issuing-ca-11111111-2222-3333-4444-555555555555"
	view, err := srv.GenerateSuccessorKey(handle, crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.Sign([]byte("before revoke"), crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("custody view did not sign before revocation: %v", err)
	}
	if _, err := srv.RevokeKey(ctx, &signerpb.RevokeKeyRequest{
		Handle: &signerpb.KeyHandle{Id: handle}, OperationId: "revoke-agid", Reason: "key_compromise",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := view.Sign([]byte("after revoke"), crypto.SignOptions{Hash: crypto.SHA256}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("cached custody view signed after revocation: %v", err)
	}
}
