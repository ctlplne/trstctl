// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"reflect"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// These tests exercise the actual event fold. An issuance event is not evidence
// that the endpoint serves the replacement, even when its legacy name says
// asset_completed. The installed reproduction issued a leaf but left the old
// endpoint untouched and returned zero findings.
func certificateProgressFixture(t *testing.T) (projections.LicensedCryptoMigrationReissue, []events.Event) {
	t.Helper()
	intent := projections.LicensedCryptoMigrationReissue{
		RunID: "certificate-run", AssetID: "certificate-asset", Kind: "certificate-key",
		Location: "api.example.test:443", Algorithm: "ECDSA", KeyBits: 256,
		Strength: "strong", QuantumVulnerable: true, TargetAlgorithm: TargetMLDSA65,
		EffectiveAlgorithm: EffectiveHybridTLS, Protocol: ProtocolACME,
	}
	when := time.Date(2026, 9, 22, 8, 0, 0, 0, time.UTC)
	started := projections.LicensedCryptoMigrationStarted{
		RunID: intent.RunID, AssetIDs: []string{intent.AssetID}, Queued: 1,
		TargetAlgorithm: intent.TargetAlgorithm, EffectiveAlgorithm: intent.EffectiveAlgorithm,
		Protocol: intent.Protocol, Reissues: []projections.LicensedCryptoMigrationReissue{intent},
	}
	issued := projections.LicensedCryptoMigrationAssetCompleted{
		RunID: intent.RunID, AssetID: intent.AssetID, Kind: intent.Kind, Location: intent.Location,
		OriginalAlgorithm: intent.Algorithm, OriginalKeyBits: intent.KeyBits,
		OriginalQuantumVulnerable: true, TargetAlgorithm: intent.TargetAlgorithm,
		EffectiveAlgorithm: intent.EffectiveAlgorithm, Protocol: intent.Protocol,
		CertificateFingerprint: "issued-leaf-fingerprint", RollbackRef: "inventory-only-reference",
	}
	return intent, []events.Event{
		{Type: projections.EventLicensedCryptoMigrationStarted, TenantID: sealedTestTenant, Time: when, Data: mustJSON(t, started)},
		{Type: projections.EventLicensedCryptoMigrationAssetCompleted, TenantID: sealedTestTenant, Time: when.Add(time.Second), Data: mustJSON(t, issued)},
	}
}

func TestPQCCertificateProgressIncludesQueuedReissue(t *testing.T) {
	intent, log := certificateProgressFixture(t)
	p := NewProgressProjection(nil)
	applyProgressLog(t, p, log[:1])
	got := p.Snapshot(sealedTestTenant, intent.RunID)
	if len(got) != 1 {
		t.Fatalf("queued certificate vanished from progress: %+v", got)
	}
	if got[0].AssetID != intent.AssetID || got[0].FindingKind != "certificate-key" || got[0].Status != "queued" {
		t.Fatalf("certificate intent not represented: %+v", got[0])
	}
}

func TestPQCCertificateProgressDistinguishesIssuanceFromVerifiedDeployment(t *testing.T) {
	intent, log := certificateProgressFixture(t)
	p := NewProgressProjection(nil)
	applyProgressLog(t, p, log)
	got := p.Snapshot(sealedTestTenant, intent.RunID)
	if len(got) != 1 {
		t.Fatalf("issued certificate vanished from progress: %+v", got)
	}
	if got[0].Status != "issued" {
		t.Fatalf("issuance-only event must be issued, never queued or applied: %+v", got[0])
	}
	if got[0].Observed != nil {
		t.Fatalf("issuance invented endpoint readback: %+v", got[0])
	}
}

func TestPQCCertificateProgressMixedRunRetainsBothKinds(t *testing.T) {
	cert, log := certificateProgressFixture(t)
	tls := testTLSIntent()
	tls.RunID = cert.RunID
	started := projections.LicensedCryptoMigrationStarted{
		RunID: cert.RunID, AssetIDs: []string{cert.AssetID, tls.AssetID}, Queued: 2,
		Reissues:    []projections.LicensedCryptoMigrationReissue{cert},
		TLSPostures: []projections.LicensedCryptoMigrationTLSPosture{tls},
	}
	log[0].Data = mustJSON(t, started)
	completed := TLSFindingCompleted{Intent: tls, Receipt: connector.TLSPostureReceipt{
		RunID: tls.RunID, FindingID: tls.AssetID, FindingKind: tls.FindingKind,
		TargetID: tls.TargetID, TargetRevision: tls.TargetRevision, Connector: tls.Connector,
		Observed: tls.Desired, Applied: true,
	}}
	log = append(log, events.Event{Type: EventTLSFindingCompleted, TenantID: sealedTestTenant,
		Time: log[1].Time.Add(time.Second), Data: mustJSON(t, completed)})
	p := testProgressRuntime().Progress
	applyProgressLog(t, p, log)
	got := p.Snapshot(sealedTestTenant, cert.RunID)
	if len(got) != 2 {
		t.Fatalf("mixed run dropped work from denominator: %+v", got)
	}
	statuses := map[string]string{}
	for _, item := range got {
		statuses[item.AssetID] = item.Status
	}
	if statuses[cert.AssetID] != "issued" || statuses[tls.AssetID] != TLSFindingApplied {
		t.Fatalf("issuance and receiver verification were conflated: %v", statuses)
	}
}

func TestPQCCertificateProgressReplayPreservesTenantAndIssuedState(t *testing.T) {
	intent, log := certificateProgressFixture(t)
	p := NewProgressProjection(nil)
	applyProgressLog(t, p, log)
	want := p.Snapshot(sealedTestTenant, intent.RunID)
	if len(want) != 1 || want[0].Status != "issued" {
		t.Fatalf("missing issuance evidence: %+v", want)
	}
	const otherTenant = "22222222-2222-4222-8222-222222222222"
	if got := p.Snapshot(otherTenant, intent.RunID); len(got) != 0 {
		t.Fatalf("foreign tenant received progress: %+v", got)
	}
	if err := p.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := p.Snapshot(sealedTestTenant, intent.RunID); len(got) != 0 {
		t.Fatalf("reset retained progress: %+v", got)
	}
	applyProgressLog(t, p, log)
	if got := p.Snapshot(sealedTestTenant, intent.RunID); !reflect.DeepEqual(got, want) {
		t.Fatalf("rebuild differs: got=%+v want=%+v", got, want)
	}
	restarted := NewProgressProjection(nil)
	applyProgressLog(t, restarted, log)
	if got := restarted.Snapshot(sealedTestTenant, intent.RunID); !reflect.DeepEqual(got, want) {
		t.Fatalf("restart differs: got=%+v want=%+v", got, want)
	}
	// The live tail can arrive after worker-side projection. Reapplying intent
	// must not turn an issued finding back into queued work.
	applyProgressLog(t, restarted, log[:1])
	if got := restarted.Snapshot(sealedTestTenant, intent.RunID); !reflect.DeepEqual(got, want) {
		t.Fatalf("duplicate intent regressed evidence: %+v", got)
	}
}

func TestPQCCertificateProgressLegacyRollbackDoesNotClaimEndpointRestore(t *testing.T) {
	intent, log := certificateProgressFixture(t)
	restore := projections.LicensedCryptoMigrationRollbackCompleted{
		RunID: intent.RunID, AssetID: intent.AssetID, Kind: intent.Kind,
		Location: intent.Location, Algorithm: intent.Algorithm, KeyBits: intent.KeyBits,
		Strength: intent.Strength, QuantumVulnerable: true,
	}
	log = append(log, events.Event{Type: projections.EventLicensedCryptoMigrationRollbackCompleted,
		TenantID: sealedTestTenant, Time: log[1].Time.Add(time.Second), Data: mustJSON(t, restore)})
	p := NewProgressProjection(nil)
	applyProgressLog(t, p, log)
	got := p.Snapshot(sealedTestTenant, intent.RunID)
	if len(got) != 1 || got[0].Status != "rollback_unverified" {
		t.Fatalf("inventory-only rollback must remain visible without claiming endpoint recovery: %+v", got)
	}
	if got[0].Observed != nil {
		t.Fatalf("inventory rollback invented endpoint readback: %+v", got[0])
	}
}
