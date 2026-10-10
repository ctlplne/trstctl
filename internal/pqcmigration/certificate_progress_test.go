// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestPQCVerifiedHostCertificateAndExactRollbackSurviveColdReplay(t *testing.T) {
	oldFP, newFP, renewedFP := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	asset := "f530ac6a-c27f-4d43-a22a-c0d8e8fcdf04"
	run := "ad659d89-d28d-4f4d-b797-071321c7f328"
	before := projections.CBOMAssetObserved{ID: asset, Kind: "certificate-key", Location: "127.0.0.1:10443",
		CertificateFingerprint: oldFP, Algorithm: "RSA", KeyBits: 2048, Strength: "weak", QuantumVulnerable: true}
	after := before
	after.CertificateFingerprint, after.Algorithm, after.KeyBits, after.Strength, after.QuantumVulnerable = newFP, TargetMLDSA65, 0, "strong", false
	served := transport.ProbeTranscript{Address: before.Location, ServerName: "apache.example.test", Vantage: transport.VantageLocal,
		Reached: true, ExpectedFingerprint: newFP, ObservedFingerprint: newFP, ObservedAtUnix: 1791610000}
	applied := CertificateFindingApplied{RunID: run, AssetID: asset, IdentityID: "identity-a", TargetID: "target-a",
		TargetRevision: "revision-a", Connector: "apache", PredecessorFingerprint: oldFP,
		CertificateFingerprint: newFP, Before: before, After: after, Transcript: served,
		AgentID: "agent-a", JobID: 7, Attempt: 2, EvidenceDigest: served.Digest(),
		ReceiptStatement: "signed statement", ReceiptSignature: "signature", ReceiptSignerFingerprint: "agent-fingerprint"}
	started := projections.LicensedCryptoMigrationStarted{RunID: run, AssetIDs: []string{asset}, Reissues: []projections.LicensedCryptoMigrationReissue{{
		RunID: run, AssetID: asset, TargetAlgorithm: TargetMLDSA65, EffectiveAlgorithm: TargetMLDSA65}}}
	stamp := time.Date(2026, 10, 10, 7, 0, 0, 0, time.UTC)
	log := []events.Event{{Type: projections.EventLicensedCryptoMigrationStarted, TenantID: sealedTestTenant, Sequence: 300414, Time: stamp, Data: mustJSON(t, started)},
		{Type: EventCertificateFindingApplied, TenantID: sealedTestTenant, Sequence: 300416, Time: stamp.Add(time.Second), Data: mustJSON(t, applied)}}
	delayedIssued := events.Event{Type: projections.EventLicensedCryptoMigrationAssetCompleted,
		TenantID: sealedTestTenant, Sequence: 300415, Time: stamp.Add(500 * time.Millisecond),
		Data: mustJSON(t, projections.LicensedCryptoMigrationAssetCompleted{
			RunID: run, AssetID: asset, TargetAlgorithm: TargetMLDSA65,
			EffectiveAlgorithm: TargetMLDSA65, CertificateFingerprint: newFP})}
	first := NewProgressProjection(nil)
	applyProgressLog(t, first, log)
	progress := first.Snapshot(sealedTestTenant, run)
	if len(progress) != 1 || progress[0].Status != TLSFindingApplied || progress[0].CertificateReadback == nil ||
		progress[0].CertificateReadback.Transcript.ObservedFingerprint != newFP {
		t.Fatalf("signed served successor was not projected: %+v", progress)
	}
	if _, found, err := first.certificateAppliedReceipt(sealedTestTenant, run, asset); err != nil || !found {
		t.Fatalf("durable applied receipt not indexed: found=%t err=%v", found, err)
	}
	renewedAfter := after
	renewedAfter.CertificateFingerprint = renewedFP
	renewedTranscript := served
	renewedTranscript.ExpectedFingerprint, renewedTranscript.ObservedFingerprint = renewedFP, renewedFP
	renewed := CertificateFindingRenewed{RunID: run, AssetID: asset, IdentityID: "identity-a",
		TargetID: "target-a", TargetRevision: "revision-a", PredecessorFingerprint: newFP,
		CertificateFingerprint: renewedFP, Before: after, After: renewedAfter, Transcript: renewedTranscript,
		AgentID: "agent-a", JobID: 9, Attempt: 1, EvidenceDigest: renewedTranscript.Digest(),
		ReceiptStatement: "renewal statement", ReceiptSignature: "renewal signature", ReceiptSignerFingerprint: "agent-fingerprint"}
	log = append(log, events.Event{Type: EventCertificateFindingRenewed, TenantID: sealedTestTenant, Sequence: 300417,
		Time: stamp.Add(2 * time.Second), Data: mustJSON(t, renewed)})
	applyProgressLog(t, first, log[2:])
	// The live command may project its event before the durable tail reaches it.
	// The tail can then deliver that same event, followed by an older applied
	// event from its own cursor. Neither may rewind the signed served leaf.
	applyProgressLog(t, first, []events.Event{log[2], delayedIssued, log[1]})
	if current, active := first.currentCertificateFingerprint(sealedTestTenant, run, asset); !active || current != renewedFP {
		t.Fatalf("signed renewal did not advance rollback successor: current=%s active=%t", current, active)
	}
	conflicting := log[2]
	changedRenewal := renewed
	changedRenewal.ReceiptStatement = "different signed statement"
	conflicting.Data = mustJSON(t, changedRenewal)
	if err := first.Apply(context.Background(), conflicting); err == nil {
		t.Fatal("same-sequence conflicting signed renewal was accepted")
	}
	if base, found, err := first.certificateAppliedReceipt(sealedTestTenant, run, asset); err != nil || !found || base.PredecessorFingerprint != oldFP {
		t.Fatalf("renewal lost exact pre-migration predecessor: base=%+v found=%t err=%v", base, found, err)
	}
	served.ExpectedFingerprint, served.ObservedFingerprint = oldFP, oldFP
	rolled := CertificateFindingRolledBack{RunID: run, AssetID: asset, TargetID: "target-a", TargetRevision: "revision-a",
		PredecessorFingerprint: oldFP, SuccessorFingerprint: renewedFP, Restored: before, Transcript: served,
		AgentID: "agent-a", JobID: 8, Attempt: 1, EvidenceDigest: served.Digest(),
		ReceiptStatement: "rollback statement", ReceiptSignature: "rollback signature", ReceiptSignerFingerprint: "agent-fingerprint"}
	log = append(log, events.Event{Type: EventCertificateFindingRolledBack, TenantID: sealedTestTenant, Sequence: 300419,
		Time: stamp.Add(3 * time.Second), Data: mustJSON(t, rolled)})
	applyProgressLog(t, first, log[3:])
	delayedFailure := events.Event{Type: EventCertificateFindingFailed,
		TenantID: sealedTestTenant, Sequence: 300418, Time: stamp.Add(2500 * time.Millisecond),
		Data: mustJSON(t, CertificateFindingFailure{RunID: run, AssetID: asset, Operation: "rollback"})}
	applyProgressLog(t, first, []events.Event{log[3], delayedFailure, log[2], delayedIssued, log[1], log[0]})
	want := first.Snapshot(sealedTestTenant, run)
	if len(want) != 1 || want[0].Status != TLSFindingRolledBack || want[0].CertificateFingerprint != oldFP ||
		want[0].CertificateReadback.Transcript.ObservedFingerprint != oldFP || want[0].EffectiveAlgorithm != "RSA" {
		t.Fatalf("rollback did not restore signed predecessor: %+v", want)
	}
	if candidates := first.RollbackLifecycleCandidates(); len(candidates) != 1 || candidates[0].IdentityID != applied.IdentityID ||
		candidates[0].PredecessorFingerprint != oldFP {
		t.Fatalf("signed rollback lifecycle recovery candidates = %+v", candidates)
	}
	restarted := NewProgressProjection(nil)
	applyProgressLog(t, restarted, log)
	if got := restarted.Snapshot(sealedTestTenant, run); !reflect.DeepEqual(got, want) {
		t.Fatalf("cold replay changed signed certificate journey: got=%+v want=%+v", got, want)
	}
}

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

func TestPQCHostSignedReadbackSurvivesProjectionRestart(t *testing.T) {
	intent := testTLSIntent()
	served := relay.PQCPostureServed{Address: "127.0.0.1:11444", ServerName: "pqc-edge.local.qa",
		TLSVersion: 0x0304, CipherSuite: 0x1302, KeyExchangeGroup: HybridTLSGroup, LeafFingerprint: "served-leaf"}
	completed := TLSFindingCompleted{Intent: intent, Receipt: connector.TLSPostureReceipt{
		RunID: intent.RunID, FindingID: intent.AssetID, FindingKind: intent.FindingKind,
		TargetID: intent.TargetID, TargetRevision: intent.TargetRevision, Connector: intent.Connector,
		Observed: intent.Desired, Applied: true,
	}, Served: &served, AgentID: "host-a", JobID: 42, Attempt: 1,
		EvidenceDigest: "signed-digest", ReceiptStatement: "statement", ReceiptSignature: "signature",
		ReceiptSignerFingerprint: "agent-fingerprint"}
	stamp := time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC)
	log := []events.Event{{Type: projections.EventLicensedCryptoMigrationStarted, TenantID: sealedTestTenant, Time: stamp,
		Data: mustJSON(t, projections.LicensedCryptoMigrationStarted{RunID: intent.RunID, AssetIDs: []string{intent.AssetID}, TLSPostures: []projections.LicensedCryptoMigrationTLSPosture{intent}})},
		{Type: EventTLSFindingCompleted, TenantID: sealedTestTenant, Time: stamp.Add(time.Second), Data: mustJSON(t, completed)}}
	first := testProgressRuntime().Progress
	applyProgressLog(t, first, log)
	want := first.Snapshot(sealedTestTenant, intent.RunID)
	if len(want) != 1 || want[0].HostReadback == nil || want[0].HostReadback.Served != served ||
		want[0].HostReadback.EvidenceDigest != "signed-digest" || want[0].Status != TLSFindingApplied {
		t.Fatalf("signed host readback missing from progress: %+v", want)
	}
	restarted := testProgressRuntime().Progress
	applyProgressLog(t, restarted, log)
	if got := restarted.Snapshot(sealedTestTenant, intent.RunID); !reflect.DeepEqual(got, want) {
		t.Fatalf("cold projection changed signed readback: got=%+v want=%+v", got, want)
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
