// SPDX-License-Identifier: LicenseRef-trstctl-EE

package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
)

func TestScheduledManifestUsesIsolatedSignerAndVerifiesOffline(t *testing.T) {
	var _ api.ComplianceScheduledSigner = (*evidenceService)(nil)
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	svc := &evidenceService{signer: signer}
	manifest := json.RawMessage(`{"format":"trstctl.compliance.scheduled-report.v1","tenant_id":"11111111-1111-1111-1111-111111111111","run_id":"22222222-2222-4222-8222-222222222222","report_type":"framework_evidence_pack"}`)
	wire, err := svc.SignScheduledManifest(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	var signed scheduledSignedEnvelope
	if err := json.Unmarshal(wire, &signed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed.Manifest, manifest) || !bytes.Equal(signed.PublicKeyDER, signer.Public().DER) {
		t.Fatalf("signed envelope changed manifest or public key: %+v", signed)
	}
	if err := crypto.VerifyMessage(signed.PublicKeyDER, signed.Manifest, signed.Signature); err != nil {
		t.Fatalf("offline verifier rejected exact manifest: %v", err)
	}
	tampered := bytes.Replace(signed.Manifest, []byte("framework_evidence_pack"), []byte("inventory_snapshot"), 1)
	if err := crypto.VerifyMessage(signed.PublicKeyDER, tampered, signed.Signature); err == nil {
		t.Fatal("changed report type still verified")
	}
	if _, err := svc.SignScheduledManifest(context.Background(), json.RawMessage(`{broken`)); err == nil {
		t.Fatal("invalid manifest reached signer")
	}
}
