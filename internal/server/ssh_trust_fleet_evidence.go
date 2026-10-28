// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/sshtrustrollout"
	"trstctl.com/trstctl/internal/store"
)

// bindSSHTrustFleetView keeps completion tied to immutable source evidence.
// Relational rows are useful indexes; changing one cannot invent a host effect.
func (s *sshTrustFleetService) bindSSHTrustFleetView(ctx context.Context, tenantID string, view *store.SSHTrustFleetRollout) error {
	unavailable := func() error {
		return fmt.Errorf("%w: SSH trust source evidence is unavailable or differs from its projection; restore the matching event projection before treating this rollout as complete", api.ErrSSHWorkflowUnavailable)
	}
	if s.log == nil {
		return unavailable()
	}
	source, found, err := s.log.EventByID(ctx, view.ID)
	if err != nil || !found || source.TenantID != tenantID || source.Type != projections.EventSSHTrustFleetStarted || source.SchemaVersion != 1 {
		return unavailable()
	}
	var started projections.SSHTrustFleetStarted
	if json.Unmarshal(source.Data, &started) != nil || projections.ValidateSSHTrustFleetStarted(started) != nil || started.ID != view.ID || started.PlanDigest != view.PlanDigest || started.Approval.RequestID != view.ApprovalRequestID {
		return unavailable()
	}
	projectedDigest, err := view.Plan.Digest()
	if err != nil || projectedDigest != started.PlanDigest || len(view.Hosts) != len(started.Plan.Hosts) {
		return unavailable()
	}
	// Reviewer metadata also comes from the canonical source, including an
	// authorized privacy rewrite, rather than independently mutable read rows.
	view.Plan, view.Requester = started.Plan, started.Approval.Requester
	view.CreatedAt, view.UpdatedAt = source.Time, source.Time
	for _, host := range view.Hosts {
		var reviewed *sshtrustrollout.Host
		for i := range started.Plan.Hosts {
			if started.Plan.Hosts[i].AgentID == host.AgentID {
				reviewed = &started.Plan.Hosts[i]
				break
			}
		}
		if reviewed == nil {
			return unavailable()
		}
		if reviewed.State == "skipped" {
			if host.State != "skipped" || host.SkipReason != reviewed.Reason || host.Receipt != nil || host.ReceiptEventID != "" {
				return unavailable()
			}
			continue
		}
		if host.State == "queued" {
			if host.Receipt != nil || host.ReceiptEventID != "" {
				return unavailable()
			}
			continue
		}
		if host.Receipt == nil || host.ReceiptEventID == "" || host.JobID == nil || host.Attempt == nil {
			return unavailable()
		}
		event, found, err := s.log.EventByID(ctx, host.ReceiptEventID)
		if err != nil || !found || event.TenantID != tenantID || event.Type != projections.EventSSHTrustFleetObserved || event.SchemaVersion != 1 {
			return unavailable()
		}
		var observed projections.SSHTrustFleetObserved
		if json.Unmarshal(event.Data, &observed) != nil || projections.ValidateSSHTrustFleetObserved(observed) != nil || observed.JobID != *host.JobID || observed.Attempt != *host.Attempt || observed.Report.State != host.State || host.CheckedAt == nil || !host.CheckedAt.Equal(observed.Report.CheckedAt.Truncate(time.Microsecond)) {
			return unavailable()
		}
		wantID := evidenceID("ssh-trust-fleet-result", tenantID, fmt.Sprintf("%s:attempt:%d", "ssh-trust-fleet:"+view.ID+":"+host.AgentID, observed.Attempt), observed.JobID)
		if event.ID != wantID {
			return unavailable()
		}
		command := sshtrustrollout.Command{RolloutID: view.ID, AgentID: host.AgentID, PublicCAKey: started.Plan.PublicCAKey, CAFingerprint: started.Plan.CAFingerprint, PlanDigest: started.PlanDigest, ReadinessDigest: reviewed.ReadinessDigest, ExpiresAt: started.Plan.ExpiresAt}
		if observed.Report.Validate(command, observed.EvidenceDigest) != nil {
			return unavailable()
		}
		canonical, err := json.Marshal(observed.Report)
		if err != nil {
			return unavailable()
		}
		projected, err := json.Marshal(host.Receipt)
		if err != nil || !bytes.Equal(canonical, projected) {
			return unavailable()
		}
		if event.Time.After(view.UpdatedAt) {
			view.UpdatedAt = event.Time
		}
	}
	return nil
}
