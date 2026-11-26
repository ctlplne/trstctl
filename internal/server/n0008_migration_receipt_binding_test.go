// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestN0008HostMigrationTranscriptMatchesCustodyVerifiedCertificate(t *testing.T) {
	result := relay.EndpointVerifyResult{
		EndpointID: "target", Transcript: transport.ProbeTranscript{
			Reached: true, ExpectedFingerprint: "agent-chosen", ObservedFingerprint: "agent-chosen",
		},
	}
	report, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{result}})
	if err != nil {
		t.Fatal(err)
	}
	claim := migrationReceiptClaim{
		stage: migration.StageSuccessor, renew: &RelayDeployIntent{TargetID: "target"},
	}
	obs := migration.Observation{}
	if err := validateVerifiedMigrationReport(claim, transport.JobOutcomeVerified,
		string(report), relay.DeploymentEvidenceDigest(result), "actual-issued", &obs); err == nil {
		t.Fatal("agent-selected listener fingerprint was accepted despite different issued certificate")
	}
	if err := validateVerifiedMigrationReport(claim, transport.JobOutcomeVerified,
		string(report), relay.DeploymentEvidenceDigest(result), "", &obs); err == nil {
		t.Fatal("host renewal was accepted without a custody-verified certificate fingerprint")
	}
	if err := validateVerifiedMigrationReport(claim, transport.JobOutcomeVerified,
		string(report), relay.DeploymentEvidenceDigest(result), "agent-chosen", &obs); err != nil {
		t.Fatalf("matching issued certificate was refused: %v", err)
	}
}

func TestN0008EmptyRollbackIntentCannotMatchNewlyBoundSuccessor(t *testing.T) {
	binding := migration.MemberBinding{RequiredAgentID: "agent", TargetID: "target", SuccessorFingerprint: "newly-issued"}
	claim := migrationReceiptClaim{rollback: &relay.RollbackIntent{RequiredAgentID: "agent", TargetID: "target"}}
	if err := validateMigrationClaimBinding(binding, "agent", claim); err == nil {
		t.Fatal("empty rollback successor matched a later issued successor")
	}
}

func TestN0008VerifiedRestoreWithMissingInventoryHaltsRunBeforeAppend(t *testing.T) {
	ctx := context.Background()
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "rollback inventory mismatch")
	const runID = "40400000-0000-4000-8000-000000000082"
	const agentID = "40400000-0000-4000-8000-000000000041"
	const predecessor = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const successor = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	binding := migration.MemberBinding{
		IssuingAuthorityID: "40400000-0000-4000-8000-000000000043",
		TargetID:           "target-a", TargetRevision: "revision-a", Connector: "nginx", Target: "edge-a",
		TargetConfig:    json.RawMessage(`{"executor":"agent","required_agent_id":"40400000-0000-4000-8000-000000000041"}`),
		RequiredAgentID: agentID,
		TrustAnchorPath: "/etc/trstctl/next-root.pem", TrustAnchorPEM: []byte("public-ca-pem"),
		TrustAnchorFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		VerifyAddress:          "127.0.0.1:443", SubjectCommonName: "edge.example.test",
		SubjectDNSNames:          []string{"edge.example.test"},
		PredecessorCertificateID: "40400000-0000-4000-8000-000000000042",
		PredecessorFingerprint:   predecessor,
	}
	start, startActions, err := migration.StartRun(migration.Run{ID: runID,
		Waves: []migration.RunWave{{ID: "canary", Ordinal: 1, Members: []migration.RunMember{{
			IdentityID: "identity-a", Binding: binding,
		}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.RecordMigrationRun(ctx, h.tenant,
		orchestrator.MigrationEventID(h.tenant, runID, "start"), start, startActions); err != nil {
		t.Fatal(err)
	}
	rolling, _, err := migration.Observe(start, migration.Observation{
		WaveID: "canary", IdentityID: "identity-a", Stage: migration.StageTrust,
		Verdict: migration.VerdictVerified,
	})
	if err != nil {
		t.Fatal(err)
	}
	rolling, err = migration.RecordSuccessorIssued(rolling, "canary", "identity-a", successor)
	if err != nil {
		t.Fatal(err)
	}
	rolling, actions, err := migration.Observe(rolling, migration.Observation{
		WaveID: "canary", IdentityID: "identity-a", Stage: migration.StageSuccessor,
		Verdict: migration.VerdictFailed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.UpdateMigrationRun(ctx, h.tenant, runID,
		orchestrator.MigrationEventID(h.tenant, runID, "begin-rollback"),
		func(migration.Run) (migration.Run, []migration.Action, error) { return rolling, actions, nil }); err != nil {
		t.Fatal(err)
	}
	intent := relay.RollbackIntent{
		Connector: binding.Connector, Target: binding.Target, TargetID: binding.TargetID,
		TargetConfig: binding.TargetConfig, RequiredAgentID: agentID,
		PredecessorFingerprint: predecessor, SuccessorFingerprint: successor,
		MigrationRunID: runID, MigrationWaveID: "canary", IdentityID: "identity-a",
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	result := relay.EndpointVerifyResult{EndpointID: binding.TargetID,
		Transcript: transport.ProbeTranscript{Reached: true,
			ExpectedFingerprint: predecessor, ObservedFingerprint: predecessor}}
	report, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{result}})
	if err != nil {
		t.Fatal(err)
	}
	if handled, err := h.srv.recordMigrationResult(ctx, h.tenant, agentID,
		relay.KindConnectorRollback, "n0008-restore-receipt", 1, payload,
		transport.JobOutcomeVerified, string(report), relay.DeploymentEvidenceDigest(result), ""); !handled || err != nil {
		t.Fatalf("verified physical rollback with mismatched inventory handled=%v err=%v", handled, err)
	}
	read, err := h.store.GetMigrationRun(ctx, h.tenant, runID)
	if err != nil || read.Run.Status != migration.RunHalted ||
		!strings.Contains(read.Run.HaltReason, "inventory") ||
		read.Run.Waves[0].Members[0].RollbackSuccessorVerdict != migration.VerdictFailed {
		t.Fatalf("inventory mismatch did not halt the run: %+v err=%v", read.Run, err)
	}
	if err := projections.New(h.store).ProjectCatchUp(ctx, h.log); err != nil {
		t.Fatalf("halted rollback poisoned catch-up: %v", err)
	}
}
