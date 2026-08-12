// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/revocationhealth"
)

// recordRevocationHealth consumes only a detail covered by the verified agent
// receipt. It runs while the lease is held; any validation/projection error
// leaves the exact claim retryable.
func (s *Server) recordRevocationHealth(
	ctx context.Context,
	tenantID, agentName, idempotencyKey string,
	jobPayload []byte,
	reportJSON, evidenceDigest string,
) error {
	if s.orch == nil || s.store == nil {
		return errors.New("revocation health receiver is not configured")
	}
	if len(reportJSON) > maxStructuredSyncReportBytes {
		return errors.New("revocation health report exceeds the receiver bound")
	}
	var intent revocationhealth.Intent
	if err := decodeStrictJSON(jobPayload, &intent); err != nil {
		return fmt.Errorf("decode revocation health command: %w", err)
	}
	if err := revocationhealth.ValidateIntent(intent); err != nil {
		return err
	}
	if idempotencyKey != intent.ID {
		return errors.New("revocation health claim key does not match the immutable probe id")
	}
	agentID := agentRowID(tenantID, agentName)
	if intent.RequiredAgentID != "" && intent.RequiredAgentID != agentID {
		return errors.New("revocation health receipt does not match the selected agent")
	}
	if len(evidenceDigest) != 64 {
		return errors.New("revocation health receipt has no SHA-256 evidence digest")
	}
	for _, r := range evidenceDigest {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return errors.New("revocation health receipt evidence digest is not lowercase hexadecimal")
		}
	}
	var report revocationhealth.Report
	if err := decodeStrictJSON([]byte(reportJSON), &report); err != nil {
		return fmt.Errorf("decode revocation health report: %w", err)
	}
	if err := revocationhealth.ValidateReport(intent, report); err != nil {
		return err
	}
	observed := revocationhealth.Observed{
		ProbeID: intent.ID, Bucket: intent.Bucket, BatchIndex: intent.BatchIndex,
		BatchCount: intent.BatchCount, AgentID: agentID, AgentName: agentName,
		EvidenceDigest: evidenceDigest, Targets: intent.Targets, Findings: report.Findings,
	}
	return s.orch.RecordRevocationHealthObservedWithEventID(ctx, tenantID,
		orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "revocation-health-observed"), observed)
}
