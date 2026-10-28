// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/agent/sshdiscovery"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/sshcollection"
	"trstctl.com/trstctl/internal/store"
)

func (a *agentService) startSSHCollection(ctx context.Context, tenantID, agentName, eventID string, payload []byte) error {
	if a.orch == nil {
		return errors.New("SSH collection orchestrator is unavailable")
	}
	command, err := a.orch.BoundSSHCollectionCommand(ctx, tenantID, eventID, payload)
	if err != nil {
		return err
	}
	if command.RequiredAgentID != agentRowID(tenantID, agentName) {
		return errors.New("SSH collection is assigned to another relay")
	}
	return a.orch.StartDiscoveryRunWithEventID(ctx, tenantID, command.ID, orchestrator.DiscoveryRelayEventID(tenantID, eventID, "ssh-collection-started"))
}

func (s *Server) recordSSHCollection(ctx context.Context, tenantID, agentName, eventID string, payload []byte, detail, digest string) error {
	command, err := s.orch.BoundSSHCollectionCommand(ctx, tenantID, eventID, payload)
	if err != nil {
		return err
	}
	collectorID := agentRowID(tenantID, agentName)
	if command.RequiredAgentID != collectorID {
		return errors.New("SSH collection report is assigned to another relay")
	}
	run, err := s.store.GetDiscoveryRun(ctx, tenantID, command.ID)
	if err != nil {
		return err
	}
	if run.SourceID != command.SourceID || run.Execution != command.Execution || run.RequiredAgentRole != command.RequiredAgentRole || run.RequiredAgentID != collectorID || run.Segment != command.Segment {
		return errors.New("SSH collection run differs from its immutable command")
	}
	if detail == "" && digest == "" {
		if discoveryRunTerminal(run.Status) {
			return nil
		}
		failed := store.DiscoveryRun{ID: command.ID, Status: "failed", Targets: len(command.Hosts), Failed: len(command.Hosts), Segment: command.Segment, ExecutedByAgentID: collectorID, Error: "SSH collection attempt failed before public readback; check the vaulted key, maintained lease and restricted helper prerequisites, then explicitly rerun."}
		for _, host := range command.Hosts {
			failed.TargetResults = append(failed.TargetResults, store.DiscoveryTargetResult{Kind: "ssh", Target: host.Address, Status: "failed", Error: "attempt_failed_before_public_readback"})
		}
		return s.orch.CompleteDiscoveryRunWithEventID(ctx, tenantID, orchestrator.DiscoveryRelayEventID(tenantID, eventID, "ssh-collection-completed"), failed)
	}
	result, err := sshcollection.DecodeReport([]byte(detail), command)
	if err != nil {
		return err
	}
	if result.EvidenceDigest() != digest {
		return errors.New("SSH collection public readback differs from its signed digest")
	}
	// A terminal result is already represented by its first immutable completion;
	// the signed-receipt first-writer gate decides whether this is the same retry.
	if discoveryRunTerminal(run.Status) {
		return nil
	}
	if run.Status == "queued" {
		if err := s.orch.StartDiscoveryRunWithEventID(ctx, tenantID, command.ID, orchestrator.DiscoveryRelayEventID(tenantID, eventID, "ssh-collection-started")); err != nil {
			return err
		}
	}
	complete := store.DiscoveryRun{ID: command.ID, Status: "succeeded", Targets: len(command.Hosts), Segment: command.Segment, ExecutedByAgentID: collectorID}
	for _, observation := range result.Results {
		state := "failed"
		if observation.Status == "observed" {
			posture, err := sshdiscovery.TrustFromSnapshot(*observation.Snapshot)
			if err != nil {
				return err
			}
			findings, err := sshdiscovery.InventoryFindings([]sshdiscovery.SSHDTrust{posture})
			if err != nil {
				return err
			}
			finding := findings[0]
			meta := finding.Metadata
			meta["agent_id"], meta["host"] = collectorID, agentName
			meta["collection_mode"], meta["target_address"] = "agentless", observation.Address
			meta["source_id"], meta["command_digest"] = command.SourceID, result.CommandDigest
			meta["command_event_id"] = eventID
			meta["coverage"] = "effective_global_settings;match_contexts_and_per_user_keys_unassessed"
			encoded, err := json.Marshal(meta)
			if err != nil {
				return err
			}
			ref := "ssh-agentless://" + command.SourceID + "/" + observation.Address + posture.ConfigPath
			if _, err := s.orch.RecordDiscoveryFindingWithEventID(ctx, tenantID, orchestrator.DiscoveryRelayEventID(tenantID, eventID, "ssh-trust\x00"+observation.Address), store.DiscoveryFinding{RunID: command.ID, SourceID: command.SourceID, Kind: sshdiscovery.TrustFindingKind, Ref: ref, Provenance: "ssh:agentless:" + observation.Address, Fingerprint: finding.Fingerprint, RiskScore: finding.RiskScore, Metadata: encoded}); err != nil {
				return err
			}
			complete.Discovered++
			state = "succeeded"
		} else {
			complete.Failed++
		}
		complete.TargetResults = append(complete.TargetResults, store.DiscoveryTargetResult{Kind: "ssh", Target: observation.Address, Status: state, Error: collectionFailure(observation.Status)})
	}
	if complete.Failed > 0 {
		complete.Status = "succeeded_with_warnings"
		complete.Error = "Some SSH targets were not observed; inspect per-target outcomes, fix account/helper/pin/egress prerequisites, and rerun."
		if complete.Discovered == 0 {
			complete.Status = "failed"
		}
	}
	return s.orch.CompleteDiscoveryRunWithEventID(ctx, tenantID, orchestrator.DiscoveryRelayEventID(tenantID, eventID, "ssh-collection-completed"), complete)
}
func collectionFailure(status string) string {
	if status == "observed" {
		return ""
	}
	return status
}
