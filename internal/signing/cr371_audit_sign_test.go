// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/signing"
)

func TestCR371AuditExportKeyCannotBypassArtifactAdmissionOverUDS(t *testing.T) {
	dir, err := os.MkdirTemp("", "cr371-")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "signer.sock")
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		_ = signing.ServeServerWithOptions(ctx, socket, signing.NewServer(), devServeOptions())
	}()
	t.Cleanup(func() { cancel(); <-serverDone; _ = os.RemoveAll(dir) })
	client := waitReady(t, socket)
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.GenerateConstrainedKeyHandle(ctx, crypto.RSA2048, "audit-export",
		[]signing.KeyPurpose{signing.PurposeAuditEvidence}, signing.PurposeAuditEvidence); err != nil {
		t.Fatal(err)
	}
	remote, err := client.SignerForHandleWithPurpose(ctx, "audit-export", signing.PurposeAuditEvidence)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.NewDigestSigningKey("audit-export", remote)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"session":"caller-chosen"}`)
	for _, kind := range []string{"pam-session-recording-manifest", "trstctl.audit-evidence/forged/v1"} {
		if _, err := client.SignArtifact(ctx, signing.ArtifactSignRequest{
			Kind: kind, TenantID: "deployment", AuthorityID: "audit-evidence", KeyID: "audit-export", Payload: payload,
		}); err == nil {
			t.Fatalf("signer admitted forbidden artifact kind %q", kind)
		}
		jws, err := key.SignArtifact(kind, payload)
		if err == nil {
			if _, verifyErr := key.JWKS().VerifyArtifact(jws, kind); verifyErr != nil {
				t.Fatalf("raw signer returned a malformed signature for %q: %v", kind, verifyErr)
			}
			t.Errorf("generic Sign bypassed audit artifact admission for %q", kind)
		}
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte("arbitrary signer-peer bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256}); err == nil {
		t.Error("generic Sign accepted an arbitrary digest on the audit-export key")
	}
	for _, kind := range []string{jose.ArtifactDoctorReceipt, "trstctl.audit-evidence/pam-recording-manifest/v1"} {
		res, err := client.SignArtifact(ctx, signing.ArtifactSignRequest{
			Kind: kind, TenantID: "deployment", AuthorityID: "audit-evidence", KeyID: "audit-export", Payload: payload,
		})
		if err != nil {
			t.Errorf("admitted artifact kind %q refused: %v", kind, err)
			continue
		}
		if _, err := key.JWKS().VerifyArtifact(string(res.Signature), kind); err != nil {
			t.Errorf("admitted artifact kind %q did not verify: %v", kind, err)
		}
	}
	typed, err := signing.AuditEvidenceSigningKey(client, remote)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := typed.SignArtifact(jose.ArtifactEvaluationPack, payload)
	if err != nil {
		t.Fatalf("first-party typed artifact client: %v", err)
	}
	if _, err := typed.JWKS().VerifyArtifact(pack, jose.ArtifactEvaluationPack); err != nil {
		t.Fatalf("first-party typed artifact signature: %v", err)
	}
}
