// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/sshtrustrollout"
	"trstctl.com/trstctl/internal/store"
)

// A retained approved append is the crash bridge: SQL and outbox loss must
// recover the same host job, while re-signing cannot replace execution facts.
func TestSSHTrustFleetFullDRAppendGapReceiptResignAndSnapshot(t *testing.T) {
	s, log, p := recordingSpine(t)
	ctx := t.Context()
	orch := orchestrator.NewOrchestrator(log, s, orchestrator.NewOutbox(s))
	public, fp, err := sshtrustrollout.CanonicalPublicCAKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt"))
	if err != nil {
		t.Fatal(err)
	}
	plan := sshtrustrollout.Plan{Name: "recovery", Reason: "Add staged public CA", PublicCAKey: public, CAFingerprint: fp, ExpiresAt: time.Now().UTC().Add(15 * time.Minute), Hosts: []sshtrustrollout.Host{{AgentID: "a2260000-0000-4000-8000-000000000001", State: "ready", ReadinessDigest: "sha256:" + strings.Repeat("a", 64)}, {AgentID: "a2260000-0000-4000-8000-000000000002", State: "skipped", Reason: "disabled"}}}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{ResourceKind: "ssh_trust_rollout", ResourceID: sshtrustrollout.ResourceID(digest), ResourceName: plan.Name, Action: "apply", Requester: "operator", FromState: "planned", ToState: "queued", TargetVersion: 1, Reason: plan.Reason, EvidenceRefs: []string{digest}, RequiredApprovals: 1, TTL: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	request, err = orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{RequestID: request.ID, IntentDigest: request.IntentDigest, Approver: "reviewer", Decision: store.ApprovalDecisionApprove})
	if err != nil {
		t.Fatal(err)
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	started := projections.SSHTrustFleetStarted{ID: orchestrator.SSHTrustFleetRolloutID(tenantA, request.ID), Plan: plan, PlanDigest: digest, Approval: use}
	raw, err := json.Marshal(started)
	if err != nil {
		t.Fatal(err)
	}
	source, err := log.Append(ctx, events.Event{ID: started.ID, TenantID: tenantA, Type: projections.EventSSHTrustFleetStarted, Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSSHTrustFleetRollout(ctx, tenantA, started.ID); !errors.Is(err, store.ErrSSHTrustFleetNotFound) {
		t.Fatalf("append/SQL gap missing: %v", err)
	}
	if err := orch.StartSSHTrustFleet(ctx, tenantA, started); err != nil {
		t.Fatalf("heal append gap: %v", err)
	}
	if err := orch.StartSSHTrustFleet(ctx, tenantA, started); err != nil {
		t.Fatalf("exact source replay: %v", err)
	}
	var jobs int
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='ssh.trust.apply'`, tenantA).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatalf("one opted-in job: count=%d err=%v", jobs, err)
	}
	report := sshtrustrollout.Report{RolloutID: started.ID, AgentID: plan.Hosts[0].AgentID, PlanDigest: digest, ReadinessDigest: plan.Hosts[0].ReadinessDigest, CAFingerprint: fp, State: "verified", Phase: "complete", Rollback: "not_needed", CAReadBack: true, EffectiveConfigReadBack: true, TrustFileSHA256: "sha256:" + strings.Repeat("c", 64), ConfigFileSHA256: "sha256:" + strings.Repeat("d", 64), Validated: true, Reloaded: true, Healthy: true, CheckedAt: time.Now().UTC()}
	_, evidence, err := report.Encode()
	if err != nil {
		t.Fatal(err)
	}
	observed := projections.SSHTrustFleetObserved{JobID: 42, Attempt: 1, Report: report, EvidenceDigest: evidence, ReceiptStatement: "first signed statement", ReceiptSignature: "c2lnbmF0dXJl", SignerFingerprint: strings.Repeat("e", 64)}
	const receiptID = "a2260000-0000-4000-8000-000000000003"
	raw, err = json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{ID: receiptID, TenantID: tenantA, Type: projections.EventSSHTrustFleetObserved, Data: raw}); err != nil {
		t.Fatal(err)
	}
	resigned := observed
	resigned.ReceiptStatement = "re-signed later after response loss"
	resigned.ReceiptSignature = "bmV3IHNpZ25hdHVyZQ=="
	resigned.SignerFingerprint = strings.Repeat("f", 64)
	if err := orch.RecordSSHTrustFleetObservation(ctx, tenantA, receiptID, resigned); err != nil {
		t.Fatalf("fresh signature blocked retained facts: %v", err)
	}
	retained, found, err := log.EventByID(ctx, receiptID)
	if err != nil || !found || !bytes.Equal(retained.Data, raw) {
		t.Fatal("re-sign retry replaced first proof")
	}
	conflict := resigned
	conflict.Report.Changed = true
	if err := orch.RecordSSHTrustFleetObservation(ctx, tenantA, receiptID, conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed facts overwrote receipt: %v", err)
	}
	assert := func(label string) {
		t.Helper()
		row, err := s.GetSSHTrustFleetRollout(ctx, tenantA, started.ID)
		if err != nil || row.State != "verified" || len(row.Hosts) != 2 || row.Hosts[0].ReceiptEventID != receiptID || row.Hosts[1].State != "skipped" || row.Hosts[0].CheckedAt == nil || !row.Hosts[0].CheckedAt.Equal(report.CheckedAt.Truncate(time.Microsecond)) {
			t.Fatalf("%s: %+v %v", label, row, err)
		}
		if _, err := s.GetSSHTrustFleetRollout(ctx, tenantB, started.ID); !errors.Is(err, store.ErrSSHTrustFleetNotFound) {
			t.Fatalf("other tenant read rollout: %v", err)
		}
	}
	assert("receipt replay")
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if count, err := p.Snapshot(ctx); err != nil || count != 1 {
		t.Fatalf("snapshot=%d err=%v", count, err)
	}
	var parentRows, hostRows int
	if err := s.SystemPool().QueryRow(ctx, `SELECT jsonb_array_length(payload->'ssh_trust_fleet_rollouts'),jsonb_array_length(payload->'ssh_trust_fleet_hosts') FROM read_model_snapshots WHERE tenant_id=$1 AND format_version=$2`, tenantA, store.SnapshotFormatVersion).Scan(&parentRows, &hostRows); err != nil || parentRows != 1 || hostRows != 2 {
		t.Fatalf("snapshot omitted exact SSH roster: parents=%d hosts=%d err=%v", parentRows, hostRows, err)
	}
	if _, err := s.SystemPool().Exec(ctx, `UPDATE projection_checkpoint SET applied_seq=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx, `TRUNCATE ssh_trust_fleet_hosts,ssh_trust_fleet_rollouts`); err != nil {
		t.Fatal(err)
	}
	if restored, err := p.RestoreFromSnapshot(ctx, log); err != nil || !restored {
		t.Fatalf("restore snapshot=%v err=%v", restored, err)
	}
	assert("snapshot restoration")
	var archive bytes.Buffer
	if _, err := backup.WriteLog(ctx, log, &archive); err != nil {
		t.Fatal(err)
	}
	restored := openLog(t)
	if _, err := backup.RestoreLog(ctx, restored, &archive); err != nil {
		t.Fatal(err)
	}
	if err := p.Rebuild(ctx, restored); err != nil {
		t.Fatalf("full restored-log rebuild: %v", err)
	}
	assert("full restored-log rebuild")
	if got, found, err := restored.EventByID(ctx, started.ID); err != nil || !found || !bytes.Equal(got.Data, source.Data) {
		t.Fatal("full restore changed approved command")
	}
	if _, err := s.SystemPool().Exec(ctx, `DELETE FROM outbox WHERE tenant_id=$1 AND destination='ssh.trust.apply'`, tenantA); err != nil {
		t.Fatal(err)
	}
	recovered := orchestrator.NewOrchestrator(restored, s, orchestrator.NewOutbox(s))
	if _, err := recovered.ReconcileOutbox(ctx, restored); err != nil {
		t.Fatalf("restore retained job intents: %v", err)
	}
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='ssh.trust.apply'`, tenantA).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatalf("recovered jobs=%d err=%v", jobs, err)
	}
}
