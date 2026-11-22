// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/kek"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

func TestCR371HistoricalAuditExportKeyRefusesRawSignAfterRestart(t *testing.T) {
	dir := t.TempDir()
	wrapper, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer wrapper.Destroy()
	keys := filepath.Join(dir, "keys")
	first, err := NewPersistentServer(NewKeyStore(keys, wrapper))
	if err != nil {
		t.Fatal(err)
	}
	key, err := first.keyspec.GenerateSigningKeyFromProto(signerpb.Algorithm_ALGORITHM_RSA_2048)
	if err != nil {
		t.Fatal(err)
	}
	// Older signers sealed this handle with a purpose constraint but no
	// artifactOnly bit. It must remain usable through the typed evidence path.
	old := keyConstraints{purposes: map[signerpb.KeyPurpose]bool{signerpb.KeyPurpose_KEY_PURPOSE_AUDIT_EVIDENCE: true}}
	if err := first.mintHeldKey("audit-export", &heldKey{signer: key, constraints: old}); err != nil {
		key.Destroy()
		t.Fatal(err)
	}
	first.Shutdown()
	second, err := NewPersistentServer(NewKeyStore(keys, wrapper))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Shutdown()
	if _, err := second.Sign(context.Background(), &signerpb.SignRequest{
		Handle: &signerpb.KeyHandle{Id: "audit-export"}, Digest: crypto.SHA256Sum([]byte("peer-chosen digest")),
		Hash: signerpb.Hash_HASH_SHA256, Purpose: signerpb.KeyPurpose_KEY_PURPOSE_AUDIT_EVIDENCE,
	}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("historical audit-export generic Sign = %v, want FailedPrecondition", err)
	}
	res, err := second.SignArtifact(context.Background(), &signerpb.SignArtifactRequest{
		Kind: jose.ArtifactDoctorReceipt, TenantId: "deployment", AuthorityId: "audit-evidence",
		KeyId: "audit-export", Payload: []byte(`{"kind":"doctor"}`),
	})
	if err != nil {
		t.Fatalf("historical audit-export SignArtifact: %v", err)
	}
	if len(res.GetSignature()) == 0 {
		t.Fatal("historical audit-export artifact has no signature")
	}
}

func TestCR371NewAuditExportKeySealsArtifactOnlyConstraint(t *testing.T) {
	dir := t.TempDir()
	wrapper, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer wrapper.Destroy()
	keys := filepath.Join(dir, "keys")
	first, err := NewPersistentServer(NewKeyStore(keys, wrapper))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.GenerateKey(context.Background(), &signerpb.GenerateKeyRequest{
		RequestedId: "audit-export", Algorithm: signerpb.Algorithm_ALGORITHM_RSA_2048,
		AllowedPurposes: []signerpb.KeyPurpose{signerpb.KeyPurpose_KEY_PURPOSE_AUDIT_EVIDENCE},
	}); err != nil {
		t.Fatal(err)
	}
	first.Shutdown()
	second, err := NewPersistentServer(NewKeyStore(keys, wrapper))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Shutdown()
	held, err := second.lookup(&signerpb.KeyHandle{Id: "audit-export"})
	if err != nil || !held.constraints.artifactOnly {
		t.Fatalf("reloaded audit-export has no sealed artifact-only constraint: %v", err)
	}
}
