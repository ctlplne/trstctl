// SPDX-License-Identifier: MPL-2.0

package historycontinuity

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
)

func TestReceiptVerifierRejectsSignatureTamperEvidenceMismatchAndWrongKey(t *testing.T) {
	key, err := jose.GenerateRSASigningKey("history-continuity-test")
	if err != nil {
		t.Fatalf("GenerateRSASigningKey: %v", err)
	}
	report := validReport()
	receipt, err := NewReceiptSigner(key)(context.Background(), report)
	if err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	evidence := evidenceFor(report, receipt)
	if err := NewReceiptVerifier(key)(context.Background(), evidence); err != nil {
		t.Fatalf("verify valid receipt: %v", err)
	}

	t.Run("signature tamper", func(t *testing.T) {
		tampered := evidence
		tampered.Receipt = cloneEvent(receipt)
		var data receiptData
		if err := json.Unmarshal(tampered.Receipt.Data, &data); err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(data.JWS, ".")
		if len(parts) != 3 || len(parts[2]) == 0 {
			t.Fatalf("unexpected compact JWS %q", data.JWS)
		}
		replacement := byte('A')
		if parts[2][0] == replacement {
			replacement = 'B'
		}
		parts[2] = string(replacement) + parts[2][1:]
		data.JWS = strings.Join(parts, ".")
		tampered.Receipt.Data, _ = json.Marshal(data)
		if err := NewReceiptVerifier(key)(context.Background(), tampered); err == nil {
			t.Fatal("verifier accepted a tampered receipt signature")
		}
	})

	t.Run("report evidence mismatch", func(t *testing.T) {
		mismatched := evidence
		mismatched.SourceStream = "TRSTCTL_EVENTS_OTHER"
		if err := NewReceiptVerifier(key)(context.Background(), mismatched); err == nil {
			t.Fatal("verifier accepted stream metadata that disagrees with the signed report")
		}
	})

	t.Run("durable report mismatch", func(t *testing.T) {
		mismatched := evidence
		mismatched.Report.MappingDigest = "different-mapping-root"
		if err := NewReceiptVerifier(key)(context.Background(), mismatched); err == nil {
			t.Fatal("verifier accepted durable report bytes that disagree with the signed report")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		wrong, err := jose.GenerateRSASigningKey("wrong-history-continuity-test")
		if err != nil {
			t.Fatal(err)
		}
		if err := NewReceiptVerifier(wrong)(context.Background(), evidence); err == nil {
			t.Fatal("verifier accepted a receipt under the wrong deployment key")
		}
	})

	t.Run("same key wrong artifact domain", func(t *testing.T) {
		tampered := evidence
		tampered.Receipt = cloneEvent(receipt)
		claims := claimsFor(receipt, report)
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		wrongDomain, err := key.SignArtifact(jose.ArtifactDoctorReceipt, payload)
		if err != nil {
			t.Fatal(err)
		}
		tampered.Receipt.Data, _ = json.Marshal(receiptData{JWS: wrongDomain})
		if err := NewReceiptVerifier(key)(context.Background(), tampered); err == nil {
			t.Fatal("verifier accepted same-key doctor evidence as a continuity receipt")
		}
	})

	t.Run("unsigned receipt field", func(t *testing.T) {
		tampered := evidence
		tampered.Receipt = cloneEvent(receipt)
		tampered.Receipt.Data = append(
			[]byte(`{"jws":`),
			append(mustJSON(t, extractJWS(t, receipt.Data)), []byte(`,"comment":"unsigned"}`)...)...,
		)
		if err := NewReceiptVerifier(key)(context.Background(), tampered); err == nil {
			t.Fatal("verifier accepted an unsigned extra receipt field")
		}
	})
}

func TestReceiptVerifierBindsRewriteProfile(t *testing.T) {
	key, err := jose.GenerateRSASigningKey("history-continuity-profile")
	if err != nil {
		t.Fatal(err)
	}
	report := validReport()
	report.Profile = "secret_rotation_schedule_v1_error_closure/v1"
	receipt, err := NewReceiptSigner(key)(context.Background(), report)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceFor(report, receipt)
	if err := NewReceiptVerifier(key)(context.Background(), evidence); err != nil {
		t.Fatalf("profiled receipt did not verify: %v", err)
	}
	opened, err := VerifyReceipt(key, receipt)
	if err != nil {
		t.Fatalf("open profiled receipt: %v", err)
	}
	if opened.Profile != report.Profile || opened.OperationID != report.OperationID {
		t.Fatalf("opened report = %#v, want signed profile/operation", opened)
	}
	evidence.Report.Profile = "different_rewrite/v1"
	if err := NewReceiptVerifier(key)(context.Background(), evidence); err == nil {
		t.Fatal("verifier accepted a rewrite profile outside the signed report")
	}
}

func TestReceiptVerifierRejectsNonCanonicalSignedClaims(t *testing.T) {
	key, err := jose.GenerateRSASigningKey("history-continuity-noncanonical")
	if err != nil {
		t.Fatal(err)
	}
	report := validReport()
	receipt, err := NewReceiptSigner(key)(context.Background(), report)
	if err != nil {
		t.Fatal(err)
	}
	canonical := claimsFor(receipt, report)
	payload, err := json.MarshalIndent(canonical, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	token, err := key.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Data, _ = json.Marshal(receiptData{JWS: token})
	if err := NewReceiptVerifier(key)(context.Background(), evidenceFor(report, receipt)); err == nil {
		t.Fatal("verifier accepted signed claims with a non-canonical JSON encoding")
	}
}

func TestAuditCheckpointProviderBindsRetentionCheckpointAndTenantGenesis(t *testing.T) {
	ctx := context.Background()
	tenantID := "22bdcaa0-7286-4c85-a318-81871274ebd6"

	genesisProvider := AuditCheckpointProvider(checkpointSource{})
	genesis, err := genesisProvider(ctx, events.TenantDataAuditView{
		Report: events.TenantDataRewriteReport{TenantID: tenantID},
	})
	if err != nil {
		t.Fatalf("genesis checkpoint: %v", err)
	}
	if genesis.BoundarySequence != 0 || genesis.BoundaryHash != "" ||
		genesis.RecordCount != 0 || genesis.IdentityDigest == "" {
		t.Fatalf("genesis checkpoint = %+v", genesis)
	}
	otherGenesis, err := genesisProvider(ctx, events.TenantDataAuditView{
		Report: events.TenantDataRewriteReport{TenantID: "c29710e1-91ca-457b-8d62-cd52e6696b83"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if otherGenesis.IdentityDigest == genesis.IdentityDigest {
		t.Fatal("genesis identity digest is not tenant-scoped")
	}

	cp := audit.Checkpoint{
		TenantID: tenantID, BoundarySeq: 41, BoundaryHash: "sealed-head",
		RecordCount: 17, ArchiveURI: "s3://audit/tenant/41.jws",
	}
	retained, err := AuditCheckpointProvider(checkpointSource{cp: cp, ok: true})(
		ctx,
		events.TenantDataAuditView{Report: events.TenantDataRewriteReport{TenantID: tenantID}},
	)
	if err != nil {
		t.Fatalf("retention checkpoint: %v", err)
	}
	if retained.BoundarySequence != cp.BoundarySeq ||
		retained.BoundaryHash != cp.BoundaryHash ||
		retained.RecordCount != uint64(cp.RecordCount) || // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
		retained.IdentityDigest == "" ||
		retained.IdentityDigest == genesis.IdentityDigest {
		t.Fatalf("mapped retention checkpoint = %+v", retained)
	}

	changedURI := cp
	changedURI.ArchiveURI = "s3://audit/tenant/resealed-41.jws"
	resealed, err := AuditCheckpointProvider(checkpointSource{cp: changedURI, ok: true})(
		ctx,
		events.TenantDataAuditView{Report: events.TenantDataRewriteReport{TenantID: tenantID}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if resealed.IdentityDigest == retained.IdentityDigest {
		t.Fatal("checkpoint identity does not bind the archive locator")
	}
}

type checkpointSource struct {
	cp  audit.Checkpoint
	ok  bool
	err error
}

func (s checkpointSource) LatestAuditCheckpoint(_ context.Context, _ string) (audit.Checkpoint, bool, error) {
	return s.cp, s.ok, s.err
}

func validReport() events.TenantDataRewriteReport {
	started := time.Now().UTC().Add(-2 * time.Second)
	return events.TenantDataRewriteReport{
		OperationID:         "rewrite-operation-1",
		TenantID:            "22bdcaa0-7286-4c85-a318-81871274ebd6",
		SourceStream:        "TRSTCTL_EVENTS",
		SourceGeneration:    "generation-1",
		TargetStream:        "TRSTCTL_EVENTS_G_REWRITE",
		TargetGeneration:    "rewrite-operation-1",
		FirstSequence:       1,
		SourceCutSequence:   11,
		ReceiptSequence:     12,
		ChangedEvents:       2,
		EnvelopeDigest:      "invariant-root",
		MappingDigest:       "mapping-root",
		SourceConfigDigest:  "source-config-digest",
		TargetConfigDigest:  "target-config-digest",
		TargetContentDigest: "target-content-digest",
		ArchiveExposure:     events.TenantDataArchiveExposureExternalCopiesMayRetainSourceBytes,
		AuditCheckpoint: events.TenantDataAuditCheckpoint{
			IdentityDigest: "genesis-identity",
		},
		SourceAuditHead: "source-audit-head",
		TargetAuditHead: "target-audit-head",
		StartedAt:       started,
		CompletedAt:     started.Add(time.Second),
	}
}

func evidenceFor(
	report events.TenantDataRewriteReport,
	receipt events.Event,
) events.TenantDataContinuityEvidence {
	return events.TenantDataContinuityEvidence{
		OperationID:     report.OperationID,
		TenantID:        report.TenantID,
		SourceStream:    report.SourceStream,
		TargetStream:    report.TargetStream,
		ReceiptSequence: report.ReceiptSequence,
		Receipt:         receipt,
		Report:          report,
	}
}

func cloneEvent(event events.Event) events.Event {
	clone := event
	clone.Data = append([]byte(nil), event.Data...)
	if event.Actor != nil {
		actor := *event.Actor
		actor.Roles = append([]string(nil), event.Actor.Roles...)
		clone.Actor = &actor
	}
	return clone
}

func extractJWS(t *testing.T, data []byte) string {
	t.Helper()
	var envelope receiptData
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.JWS
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
