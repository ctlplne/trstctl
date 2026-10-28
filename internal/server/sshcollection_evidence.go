// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// bindAgentlessSSHPosture checks the public observation's immutable source,
// rather than letting a mutable row decorate invented facts with a real job ID.
// Triage-only extra metadata is harmless; every observed field must still match.
func (s *Server) bindAgentlessSSHPosture(ctx context.Context, tenantID string, row *store.SSHTrustPosture) error {
	var meta map[string]string
	if err := json.Unmarshal(row.Metadata, &meta); err != nil {
		return err
	}
	if meta["collection_mode"] != "agentless" {
		return nil
	}
	if s.log == nil || meta["command_event_id"] == "" || meta["target_address"] == "" {
		return errors.New("agentless SSH posture has no retained immutable observation")
	}
	id := orchestrator.DiscoveryRelayEventID(tenantID, meta["command_event_id"], "ssh-trust\x00"+meta["target_address"])
	event, found, err := s.log.EventByID(ctx, id)
	if err != nil {
		return err
	}
	if !found || event.TenantID != tenantID || event.Type != projections.EventDiscoveryFindingRecorded {
		return errors.New("agentless SSH posture observation is unavailable; restore its source history and replay")
	}
	if err := projections.ValidateSchemaVersion(event); err != nil {
		return err
	}
	var proof projections.DiscoveryFindingRecorded
	if err := decodeStrictJSON(event.Data, &proof); err != nil {
		return err
	}
	if proof.SourceID != row.SourceID || proof.RunID != row.RunID || proof.Kind != store.SSHTrustFindingKind || proof.Ref != row.ConfigPath || proof.Fingerprint != row.Fingerprint {
		return errors.New("agentless SSH posture identity differs from its immutable observation")
	}
	var observed map[string]string
	if err := json.Unmarshal(proof.Metadata, &observed); err != nil {
		return err
	}
	if observed["collection_mode"] != "agentless" {
		return errors.New("SSH observation does not establish an agentless collection")
	}
	for key, value := range observed {
		if actual, present := meta[key]; !present || actual != value {
			return errors.New("agentless SSH posture facts differ from their immutable observation; replay the projection")
		}
	}
	// Freshness comes from the source observation, never an edited SQL timestamp.
	row.LastSeenAt = event.Time.UTC()
	return nil
}
