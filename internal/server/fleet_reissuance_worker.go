// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// handleFleetReissuanceBatch is the durable D6 command-side state machine.
// The request path publishes only batch one. This receiver publishes replacement
// work for the current cursor, waits without spending its retry budget, and only
// publishes the next batch after signature-verified endpoint receipts pass.
func (d *issuanceDispatcher) handleFleetReissuanceBatch(ctx context.Context, m orchestrator.Message) error {
	var command orchestrator.FleetReissuanceBatchCommand
	if err := json.Unmarshal(m.Payload, &command); err != nil {
		return fmt.Errorf("server: decode fleet reissuance batch: %w", err)
	}
	if command.RunID == "" || command.BatchIndex <= 0 {
		return fmt.Errorf("server: fleet reissuance batch requires run_id and positive batch_index")
	}
	run, err := d.store.GetIncidentFleetReissuanceRun(ctx, m.TenantID, command.RunID)
	if err != nil {
		return err
	}
	if run.Status == "executed" || run.Status == "rollback_recorded" || command.BatchIndex < run.NextBatchIndex {
		return nil
	}
	if run.Status == "paused" {
		return orchestrator.DeferDelivery(fmt.Errorf("server: fleet reissuance %s is operator-paused", run.ID))
	}
	if run.Status == "halted" {
		return orchestrator.DeferDelivery(fmt.Errorf("server: fleet reissuance %s is halted: %s", run.ID, run.HaltedReason))
	}
	if run.Status != "running" {
		return fmt.Errorf("server: fleet reissuance %s has unsupported status %q", run.ID, run.Status)
	}
	if command.BatchIndex != run.NextBatchIndex {
		return fmt.Errorf("server: fleet reissuance %s cursor is batch %d, command names batch %d", run.ID, run.NextBatchIndex, command.BatchIndex)
	}
	batchOffset := command.BatchIndex - 1
	if batchOffset < 0 || batchOffset >= len(run.Batches) {
		return fmt.Errorf("server: fleet reissuance %s batch %d is outside %d planned batches", run.ID, command.BatchIndex, len(run.Batches))
	}
	batch := &run.Batches[batchOffset]
	if batch.Status == servedstatus.FleetBatchQueued {
		if err := d.publishFleetBatchReplacements(ctx, m.TenantID, &run, batch); err != nil {
			return err
		}
		batch.Status = servedstatus.FleetBatchWaitingVerification
		batch.HealthGate = servedstatus.FleetGateNotEvaluated
		if command.BatchIndex == 1 {
			run.Phase = "canary_waiting_verification"
		} else {
			run.Phase = fmt.Sprintf("batch_%d_waiting_verification", command.BatchIndex)
		}
		if _, err := d.orch.RecordIncidentFleetReissuance(ctx, m.TenantID, run); err != nil {
			return err
		}
		return orchestrator.DeferDelivery(fmt.Errorf("server: fleet batch %d waits for signed endpoint verification", command.BatchIndex))
	}

	outcome, err := d.store.SummarizeFleetVerification(ctx, m.TenantID, batch.ReplacementIdentityIDs)
	if err != nil {
		return err
	}
	if outcome.Failed > 0 {
		batch.Status = servedstatus.FleetBatchFailed
		batch.HealthGate = servedstatus.FleetGateFailed
		run.Status = "halted"
		run.Phase = fmt.Sprintf("batch_%d_verification_failed", command.BatchIndex)
		run.HaltedReason = fmt.Sprintf("batch %d has %d signature-verified endpoint failure receipt(s); %d later batch(es) remain unpublished", command.BatchIndex, outcome.Failed, len(run.Batches)-command.BatchIndex)
		for i := command.BatchIndex; i < len(run.Batches); i++ {
			run.Batches[i].Status = servedstatus.FleetBatchHalted
		}
		if _, err := d.orch.RecordIncidentFleetReissuance(ctx, m.TenantID, run); err != nil {
			return err
		}
		return orchestrator.DeferDelivery(fmt.Errorf("server: %s", run.HaltedReason))
	}
	if outcome.Unverified > 0 || outcome.Verified != len(batch.ReplacementIdentityIDs) {
		return orchestrator.DeferDelivery(fmt.Errorf("server: fleet batch %d has %d signed verification receipt(s) and waits for %d", command.BatchIndex, outcome.Verified, outcome.Unverified))
	}

	if err := d.revokeVerifiedFleetBatch(ctx, m.TenantID, &run, *batch); err != nil {
		return err
	}
	batch.Status = servedstatus.FleetBatchExecuted
	batch.HealthGate = servedstatus.FleetGatePassed
	if command.BatchIndex == len(run.Batches) {
		run.Status = "executed"
		run.Phase = "fleet_reissued_and_compromised_revoked"
		run.NextBatchIndex = len(run.Batches) + 1
		run.HaltedReason = ""
		_, err := d.orch.RecordIncidentFleetReissuance(ctx, m.TenantID, run)
		return err
	}

	run.NextBatchIndex++
	run.Phase = fmt.Sprintf("batch_%d_queued", run.NextBatchIndex)
	run.Batches[run.NextBatchIndex-1].Status = servedstatus.FleetBatchQueued
	run.Batches[run.NextBatchIndex-1].HealthGate = servedstatus.FleetGateNotEvaluated
	_, err = d.orch.RecordIncidentFleetReissuanceAndEnqueueBatch(ctx, m.TenantID, run, run.NextBatchIndex)
	return err
}

func (d *issuanceDispatcher) publishFleetBatchReplacements(
	ctx context.Context, tenantID string, run *store.IncidentFleetReissuanceRun, batch *store.FleetReissuanceBatch,
) error {
	for i, compromisedID := range batch.IdentityIDs {
		compromised, err := d.store.GetIdentity(ctx, tenantID, compromisedID)
		if err != nil {
			return err
		}
		if i >= len(batch.ReplacementIdentityIDs) {
			return fmt.Errorf("server: fleet batch %d has no deterministic replacement for identity %s", batch.Index, compromisedID)
		}
		replacementID := batch.ReplacementIdentityIDs[i]
		replacement, err := d.orch.EnsureIdentity(ctx, tenantID, replacementID, store.Identity{
			Kind: compromised.Kind, Name: fleetWorkerReplacementName(compromised.Name, batch.Index, i),
			OwnerID: compromised.OwnerID, IssuerID: compromised.IssuerID,
			Attributes: fleetWorkerReplacementAttributes(run.ID, compromised.ID, run.Connector, run.Target, compromised.Attributes),
		})
		if err != nil {
			return err
		}
		if !containsFleetID(run.ReplacementIdentityIDs, replacement.ID) {
			run.ReplacementIdentityIDs = append(run.ReplacementIdentityIDs, replacement.ID)
			run.RollbackRefs = append(run.RollbackRefs, "replacement:"+replacement.ID)
		}
		if replacement.Status == string(orchestrator.StateRequested) {
			reason := "fleet replacement issued while compromised identity remains active: " + run.Reason
			key := fmt.Sprintf("fleet:%s:batch:%d:issue:%s", run.ID, batch.Index, replacement.ID)
			if err := d.orch.TransitionWithIdempotency(ctx, tenantID, replacement.ID, orchestrator.StateIssued, reason, key); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *issuanceDispatcher) revokeVerifiedFleetBatch(
	ctx context.Context, tenantID string, run *store.IncidentFleetReissuanceRun, batch store.FleetReissuanceBatch,
) error {
	for _, identityID := range batch.IdentityIDs {
		state, err := d.orch.State(ctx, tenantID, identityID)
		if err != nil {
			return err
		}
		if state != orchestrator.StateRevoked && state != orchestrator.StateRetired {
			key := fmt.Sprintf("fleet:%s:batch:%d:revoke:%s", run.ID, batch.Index, identityID)
			if err := d.orch.TransitionWithIdempotency(ctx, tenantID, identityID, orchestrator.StateRevoked,
				"compromised identity revoked only after signed replacement verification: "+run.Reason, key); err != nil {
				return err
			}
		}
		if !containsFleetID(run.RevokedIdentityIDs, identityID) {
			run.RevokedIdentityIDs = append(run.RevokedIdentityIDs, identityID)
		}
	}
	return nil
}

func fleetWorkerReplacementName(name string, batchIndex, itemIndex int) string {
	base := strings.TrimSpace(name)
	if base == "" {
		base = "identity"
	}
	return fmt.Sprintf("%s-fleet-reissue-%d-%d", base, batchIndex, itemIndex+1)
}

func fleetWorkerReplacementAttributes(runID, replaces, connectorName, target string, existing json.RawMessage) json.RawMessage {
	attrs := map[string]any{}
	_ = json.Unmarshal(existing, &attrs)
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs["fleet_reissuance_run_id"] = runID
	attrs["incident_replaces_identity_id"] = replaces
	attrs["connector"] = connectorName
	attrs["target"] = target
	body, _ := json.Marshal(attrs)
	return body
}

func containsFleetID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
