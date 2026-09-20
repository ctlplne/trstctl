// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// TestLegacyAuditKeyMigratesInsidePersistentSigner pins the only allowed upgrade
// path for the old control-plane-owned audit PEM: the isolated signer imports it,
// seals it under a purpose-bound handle, and removes the plaintext file only
// after the key survives a restart (AUD-63 / AN-4 / AN-8).
func TestLegacyAuditKeyMigratesInsidePersistentSigner(t *testing.T) {
	legacy, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatalf("GenerateRSASigningKey: %v", err)
	}
	pemBytes, err := legacy.MarshalPrivateKey()
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	legacyPath := filepath.Join(t.TempDir(), "audit-signing-key.pem")
	if err := os.WriteFile(legacyPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write legacy key: %v", err)
	}

	storeDir := t.TempDir()
	kek := testKEK(t)
	s1, err := signing.NewPersistentServer(signing.NewKeyStore(storeDir, kek))
	if err != nil {
		t.Fatalf("NewPersistentServer boot 1: %v", err)
	}
	migrated, err := s1.MigrateLegacySigningKeyFile(
		legacyPath,
		"audit-export",
		[]signing.KeyPurpose{signing.PurposeAuditEvidence},
	)
	if err != nil {
		t.Fatalf("MigrateLegacySigningKeyFile: %v", err)
	}
	if !migrated {
		t.Fatal("legacy key was not reported as migrated")
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("legacy plaintext still exists after durable migration: %v", err)
	}

	ctx := context.Background()
	handle := &signerpb.KeyHandle{Id: "audit-export"}
	pub1, err := s1.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: handle})
	if err != nil {
		t.Fatalf("GetPublicKey boot 1: %v", err)
	}
	digest := make([]byte, 32)
	if _, err := s1.Sign(ctx, &signerpb.SignRequest{
		Handle: handle, Digest: digest, Hash: signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_AUDIT_EVIDENCE,
	}); err != nil {
		t.Fatalf("audit-purpose Sign: %v", err)
	}
	if _, err := s1.Sign(ctx, &signerpb.SignRequest{
		Handle: handle, Digest: digest, Hash: signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_GENERIC,
	}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("generic Sign status = %v, want FailedPrecondition", status.Code(err))
	}

	artifactPayload := []byte(`{"format":"trstctl.doctor.v1"}`)
	artifact, err := s1.SignArtifact(ctx, &signerpb.SignArtifactRequest{
		Kind: jose.ArtifactDoctorReceipt, TenantId: "deployment", AuthorityId: "audit-evidence",
		KeyId: "audit-export", Payload: artifactPayload,
	})
	if err != nil {
		t.Fatalf("SignArtifact doctor receipt: %v", err)
	}
	gotPayload, err := legacy.JWKS().VerifyArtifact(string(artifact.GetSignature()), jose.ArtifactDoctorReceipt)
	if err != nil {
		t.Fatalf("verify artifact JWS: %v", err)
	}
	if !bytes.Equal(gotPayload, artifactPayload) {
		t.Fatalf("artifact payload = %q, want %q", gotPayload, artifactPayload)
	}
	parts := strings.Split(string(artifact.GetSignature()), ".")
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode artifact header: %v", err)
	}
	var protected map[string]any
	if err := json.Unmarshal(header, &protected); err != nil {
		t.Fatalf("parse artifact header: %v", err)
	}
	if protected["trstctl_artifact"] != jose.ArtifactDoctorReceipt {
		t.Fatalf("protected artifact domain = %v", protected["trstctl_artifact"])
	}
	for name, req := range map[string]*signerpb.SignArtifactRequest{
		"unknown kind": {
			Kind: "trstctl.audit-evidence/not-admitted/v1", TenantId: "deployment", AuthorityId: "audit-evidence",
			KeyId: "audit-export", Payload: artifactPayload,
		},
		"wrong authority": {
			Kind: jose.ArtifactDoctorReceipt, TenantId: "deployment", AuthorityId: "other",
			KeyId: "audit-export", Payload: artifactPayload,
		},
	} {
		if _, err := s1.SignArtifact(ctx, req); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s status = %v, want FailedPrecondition", name, status.Code(err))
		}
	}

	s2, err := signing.NewPersistentServer(signing.NewKeyStore(storeDir, kek))
	if err != nil {
		t.Fatalf("NewPersistentServer boot 2: %v", err)
	}
	pub2, err := s2.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: handle})
	if err != nil {
		t.Fatalf("GetPublicKey boot 2: %v", err)
	}
	if !bytes.Equal(pub1.GetPublicKey(), pub2.GetPublicKey()) {
		t.Fatal("migrated audit key changed across signer restart")
	}
	if _, err := s2.Sign(ctx, &signerpb.SignRequest{
		Handle: handle, Digest: digest, Hash: signerpb.Hash_HASH_SHA256,
		Purpose: signerpb.KeyPurpose_KEY_PURPOSE_AUDIT_EVIDENCE,
	}); err != nil {
		t.Fatalf("audit-purpose Sign after restart: %v", err)
	}

	migrated, err = s2.MigrateLegacySigningKeyFile(
		legacyPath,
		"audit-export",
		[]signing.KeyPurpose{signing.PurposeAuditEvidence},
	)
	if err != nil {
		t.Fatalf("idempotent migration: %v", err)
	}
	if migrated {
		t.Fatal("missing legacy file was reported as migrated")
	}
}
