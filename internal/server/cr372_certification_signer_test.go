// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/signing"
)

// A completed campaign must be signed by the shipped, isolated signer using
// the same audit key that the control plane binds in production.
func TestCR372CertificationResultOverShippedSigner(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "signer-auth.bin")
	authorizer, err := signing.LoadOrCreateAuthorizer(authFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authorizer.Destroy)
	run := dodStartShippedSignerProcess(t, dir, "cr372", authFile, "", authorizer)
	key, err := loadRunAuditSigningKey(context.Background(), run.signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	body, err := json.Marshal(certificationResult{CampaignID: "campaign-1", TenantID: "tenant-1", Name: "quarterly",
		Scope: PAMCertificationScope, RequestedBy: "operator-1", CreatedAt: now, CompletedAt: now,
		Certified: 1, Items: []certificationResultItem{{ItemID: "item-1", NHIID: "nhi-1", Status: "certified", DecisionBy: "operator-2"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.SignArtifact(jose.ArtifactAuditExport, body); err != nil {
		t.Fatalf("control audit kind: %v", err)
	}
	if _, err := key.SignArtifact(jose.ArtifactPAMRecordingManifest, body); err != nil {
		t.Fatalf("recording manifest audit kind: %v", err)
	}
	signature, err := key.SignArtifact(CertificationResultArtifact, body)
	if err != nil {
		t.Fatalf("production audit key refused a completed certification result: %v", err)
	}
	verified, err := key.JWKS().VerifyArtifact(signature, CertificationResultArtifact)
	if err != nil || string(verified) != string(body) {
		t.Fatalf("certification result signature did not verify: %v", err)
	}
	if _, err := key.SignArtifact("pam-session-recording-manifest", body); err == nil {
		t.Fatal("isolated signer admitted an unrelated legacy artifact kind")
	}
}
