// SPDX-License-Identifier: BUSL-1.1

package backup

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
)

func TestSignedDrillEvidenceBindsWholeAttestationAndDomain(t *testing.T) {
	t.Parallel()
	key, err := jose.GenerateRSASigningKey("drill-key")
	if err != nil {
		t.Fatal(err)
	}
	att := DrillAttestation{
		Outcome: DrillFailed, StartedAt: time.Unix(100, 0).UTC(),
		CompletedAt: time.Unix(130, 0).UTC(), RPOSeconds: 900,
		RTOSeconds: 30, Detail: "restore failed closed",
		Limitations: []string{"ephemeral target"},
	}
	evidence, err := SignDrillEvidence(context.Background(), key, "drill-1", att, 10*time.Minute, time.Minute)
	if err != nil {
		t.Fatalf("SignDrillEvidence: %v", err)
	}
	if evidence.SchemaVersion != DrillEvidenceSchemaVersion || evidence.DrillID != "drill-1" {
		t.Fatalf("signed identity = %+v", evidence)
	}
	if evidence.SignerKeyID != key.KeyID() || evidence.SignerAlgorithm != "RS256" || len(evidence.VerificationJWKS) == 0 {
		t.Fatalf("signer identity/material missing: %+v", evidence)
	}
	if err := VerifyDrillEvidence(evidence, key.JWKS()); err != nil {
		t.Fatalf("VerifyDrillEvidence: %v", err)
	}

	tampered := evidence
	tampered.Attestation.Detail = "restore passed"
	if err := VerifyDrillEvidence(tampered, key.JWKS()); err == nil {
		t.Fatal("verification accepted a changed attestation")
	}
	tampered = evidence
	tampered.AlertReason = ""
	if err := VerifyDrillEvidence(tampered, key.JWKS()); err == nil {
		t.Fatal("verification accepted removal of the signed failure alert")
	}
	tampered = evidence
	tampered.RPOObjectiveNanoseconds = int64(24 * time.Hour)
	if err := VerifyDrillEvidence(tampered, key.JWKS()); err == nil {
		t.Fatal("verification accepted changed signed recovery objectives")
	}

	other, err := key.SignArtifact(jose.ArtifactDoctorReceipt, mustJSON(t, evidence.DrillEvidenceBody))
	if err != nil {
		t.Fatal(err)
	}
	tampered = evidence
	tampered.Signature = other
	if err := VerifyDrillEvidence(tampered, key.JWKS()); err == nil {
		t.Fatal("verification accepted a same-key signature from another evidence domain")
	}
	tampered = evidence
	tampered.SignerKeyID = "some-other-key"
	tampered.Signature, err = key.SignArtifact(jose.ArtifactRestoreDrill, mustJSON(t, tampered.DrillEvidenceBody))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDrillEvidence(tampered, key.JWKS()); err == nil {
		t.Fatal("verification accepted signer identity different from the protected JWS kid")
	}
}

func TestSignedDrillEvidenceRejectsEmbeddedAttackerKey(t *testing.T) {
	t.Parallel()
	trusted, err := jose.GenerateRSASigningKey("trusted")
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := jose.GenerateRSASigningKey("attacker")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := SignDrillEvidence(context.Background(), attacker, "drill-2", DrillAttestation{
		Outcome: DrillRestored, StartedAt: time.Unix(200, 0).UTC(), CompletedAt: time.Unix(201, 0).UTC(),
	}, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDrillEvidence(evidence, trusted.JWKS()); err == nil {
		t.Fatal("verification trusted the attacker-controlled JWKS embedded in the record")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
