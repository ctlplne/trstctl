// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

func TestServedLargeSealedManifestExecutesEveryDependentA267(t *testing.T) {
	servedDependentRotationScenario(t, nil, false, dependentRotationOptions{ManifestLargeReview: true, ManifestExecution: true})
}
func largeDependentSuccessReport(step servicedependents.RotationStep) servicedependents.StepReport {
	report := servicedependents.StepReport{RotationID: step.RotationID, PlanDigest: step.PlanDigest, StepID: step.ID, Direction: step.Direction, Status: "succeeded", ObservedAt: time.Now().UTC()}
	switch step.Action {
	case servicedependents.Preflight:
		if step.Service != nil {
			report.Runtime = &windependents.Runtime{Running: true, ProcessID: 101, AccountSID: step.AccountSID}
		}
		if step.Pool != nil {
			report.Runtime = &windependents.Runtime{Running: true, AccountSID: step.AccountSID}
		}
	case servicedependents.Stop:
		report.Runtime = &windependents.Runtime{}
		if step.Pool != nil {
			report.PoolProof = &windependents.PoolRestartProof{Name: step.Pool.Name, AccountSID: step.AccountSID, ConfigSHA256: step.Pool.ConfigSHA256, WasStarted: true, StoppedObserved: true, PreviousPIDs: []uint32{101}}
		}
	case servicedependents.Start, servicedependents.Probe:
		report.Runtime = &windependents.Runtime{Running: true, ProcessID: 202, AccountSID: step.AccountSID}
		if step.Pool != nil {
			report.PoolProof = &windependents.PoolRestartProof{Name: step.Pool.Name, AccountSID: step.AccountSID, ConfigSHA256: step.Pool.ConfigSHA256, WasStarted: true, StoppedObserved: true, StartedObserved: true, PreviousPIDs: step.PreviousPIDs}
		}
	}
	if step.Action == servicedependents.Probe {
		report.Functional = &servicedependents.FunctionalProof{ProbeID: step.ProbeID, Challenge: step.Challenge, ProcessID: 202, AccountSID: step.AccountSID, EvidenceSHA256: strings.Repeat("f", 64)}
		if step.Task != nil {
			report.Runtime = nil
			report.Functional.ProcessID = 0
			instance := uuid.NewString()
			report.TaskProof = &windependents.TaskRunProof{StartedAt: step.NotBefore, CompletedAt: report.ObservedAt, Path: step.Task.Path, AccountSID: step.AccountSID, InstanceID: instance, StartRecordID: 11, CompletionRecordID: 13, Actions: []windependents.TaskActionResult{{RecordID: 12, ResultCode: 0}}}
			report.Functional.TaskInstanceID = instance
		}
	}
	return report
}
func servedLargeDependentExecution(t *testing.T, h, second *roleHarness, token, root, path string, sealed store.ServiceDependentManifest, entries []servicedependents.RotationManifestEntry, directory *dependentDirectoryBoundary) {
	t.Helper()
	ctx := t.Context()
	code, raw := secretsReq(t, h.servedHarness, http.MethodGet, path, token, nil)
	var review struct {
		Intent servicedependents.RotationIntent `json:"intent"`
		Digest string                           `json:"intent_digest"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &review) != nil || review.Digest == "" || review.Intent.Plan.Manifest == nil || review.Intent.Plan.Manifest.Digest != sealed.Seal.Digest {
		t.Fatal("large sealed account has no exact queue intent")
	}
	code, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, root+"/rotations", token, "owned-large-execution", map[string]any{"intent": review.Intent, "intent_digest": review.Digest, "acknowledge_single_phase": true})
	var queued struct {
		Rotation store.ServiceDependentRotation `json:"rotation"`
	}
	if code != http.StatusAccepted || json.Unmarshal(raw, &queued) != nil || queued.Rotation.ID != sealed.Header.ID {
		t.Fatalf("large account split or could not queue: %d %s", code, raw)
	}
	seen := map[string]bool{}
	counts := map[string]int{}
	ranks := map[string]int{servicedependents.Preflight: 0, servicedependents.Stop: 1, servicedependents.Update: 2, servicedependents.Start: 3, servicedependents.Probe: 4}
	lastRank := -1
	lastOrdinal := int64(-1)
	deadline := time.Now().Add(18 * time.Minute)
	var final store.SecretStaticRotationCommand
	for time.Now().Before(deadline) {
		command, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, queued.Rotation.CommandID)
		if err != nil {
			t.Fatal(err)
		}
		if command.Terminal() {
			final = command
			break
		}
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE outbox SET next_attempt_at=now() WHERE tenant_id=$1 AND id=$2 AND status='pending'`, h.tenant, command.OutboxID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := h.srv.outbox.DispatchOneScoped(ctx, h.srv.obHandler, orchestrator.DestinationScope{IncludeDestinations: []string{store.SecretStaticRotationDestination}}); err != nil {
			t.Fatal(err)
		}
		var selected *roleHarness
		var job *transport.ClaimedJob
		for _, host := range []*roleHarness{h, second} {
			result, err := host.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{servicedependents.RotationDestination}, Limit: 1, LeaseSeconds: 120})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Jobs) > 0 {
				selected = host
				job = &result.Jobs[0]
				break
			}
		}
		if job == nil {
			continue
		}
		step, err := servicedependents.DecodeRotationStep(job.Payload)
		if err != nil || step.ManifestPosition == nil {
			t.Fatal("large native grant lost its exact source location", err)
		}
		position := step.ManifestPosition
		if position.EntryOrdinal < 0 || position.EntryOrdinal >= int64(len(entries)) || entries[position.EntryOrdinal].Ref != step.Ref || seen[step.ID] || step.RotationID != sealed.Header.ID {
			t.Fatal("large source locator duplicated, omitted or substituted a native effect")
		}
		rank := ranks[step.Action]
		if rank < lastRank || rank == lastRank && (step.Action == servicedependents.Stop && position.EntryOrdinal >= lastOrdinal || step.Action != servicedependents.Stop && position.EntryOrdinal <= lastOrdinal) {
			t.Fatal("large native sequence lost global stage/reverse stop order")
		}
		lastRank = rank
		lastOrdinal = position.EntryOrdinal
		if step.Action == servicedependents.Preflight && directory.applied != 0 || step.Action != servicedependents.Preflight && (counts[servicedependents.Preflight] != len(entries) || directory.applied != 1) {
			t.Fatal("directory reset crossed an incomplete account preflight barrier")
		}
		if step.Action == servicedependents.Update {
			material, err := selected.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt})
			if err != nil || len(material.Items) != 1 {
				t.Fatal("large exact native update could not redeem its generation", err)
			}
			var current struct {
				Password secret.JSONBytes `json:"password"`
			}
			directory.mu.Lock()
			err = json.Unmarshal(directory.current.Bytes(), &current)
			directory.mu.Unlock()
			same := err == nil && bytes.Equal(current.Password, material.Items[0].Value)
			secret.Wipe(current.Password)
			secret.Wipe(material.Items[0].Value)
			if !same {
				t.Fatal("large native update redeemed another directory generation")
			}
		}
		report := largeDependentSuccessReport(step)
		if err := report.Validate(step); err != nil {
			t.Fatal("invalid signed native boundary fixture", err)
		}
		raw, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := selected.client.ReportJobResult(ctx, selected.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(raw), crypto.SHA256Hex(raw)))
		if err != nil || !receipt.Accepted {
			t.Fatal("large native report rejected", err)
		}
		seen[step.ID] = true
		counts[step.Action]++
		if len(seen)%256 == 0 {
			t.Logf("A267_LARGE_EXECUTION_PROGRESS native_effects=%d preflights=%d directory_resets=%d", len(seen), counts[servicedependents.Preflight], directory.applied)
		}
	}
	if final.Phase != store.SecretStaticRotationCompleted || directory.applied != 1 || directory.restored != 0 {
		t.Fatalf("large single-account native operation did not complete: phase=%s counts=%v", final.Phase, counts)
	}
	expected := map[string]int{servicedependents.Preflight: 1536, servicedependents.Stop: 1024, servicedependents.Update: 1536, servicedependents.Start: 1024, servicedependents.Probe: 1536}
	for action, want := range expected {
		if counts[action] != want {
			t.Fatalf("large account omitted %s effects: %d want%d", action, counts[action], want)
		}
	}
	parent, err := h.store.GetServiceDependentRotation(ctx, h.tenant, queued.Rotation.ID)
	if err != nil || parent.ManifestCursor == nil || parent.ManifestCursor.Position.Stage != servicedependents.ManifestComplete {
		t.Fatal("large root has no source-proven final cursor", err)
	}
	var roots int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM service_account_rotations WHERE tenant_id=$1`, h.tenant).Scan(&roots)
	}); err != nil || roots != 1 {
		t.Fatal("large account was split across independent rotations", err)
	}
	t.Logf("A267_LARGE_EXECUTION_OK refs=%d native_effects=%d one_root=%s one_directory_reset=1; signed host fixtures, not native Windows execution", len(entries), len(seen), queued.Rotation.ID)
}
