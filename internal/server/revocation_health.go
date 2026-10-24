// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/revocationhealth"
)

// errRevocationReportRefused marks a signed report that can never validate:
// resending it cannot change the answer, so the job is closed as failed rather
// than left for the agent to retry forever (B13-7).
var errRevocationReportRefused = errors.New("revocation health report refused")

// recordRevocationHealth consumes only a detail covered by the verified agent
// receipt. It runs while the lease is held; a projection error leaves the exact
// claim retryable, and a report that can never validate is refused.
func (s *Server) recordRevocationHealth(
	ctx context.Context,
	tenantID, agentName, idempotencyKey string,
	jobPayload []byte,
	reportJSON, evidenceDigest string,
) error {
	if s.orch == nil || s.store == nil {
		return errors.New("revocation health receiver is not configured")
	}
	refused := func(err error) error { return fmt.Errorf("%w: %w", errRevocationReportRefused, err) }
	if len(reportJSON) > maxStructuredSyncReportBytes {
		return refused(errors.New("revocation health report exceeds the receiver bound"))
	}
	var intent revocationhealth.Intent
	if err := decodeStrictJSON(jobPayload, &intent); err != nil {
		return refused(fmt.Errorf("decode revocation health command: %w", err))
	}
	if err := revocationhealth.ValidateIntent(intent); err != nil {
		return refused(err)
	}
	if idempotencyKey != intent.ID {
		return refused(errors.New("revocation health claim key does not match the immutable probe id"))
	}
	agentID := agentRowID(tenantID, agentName)
	if intent.RequiredAgentID != "" && intent.RequiredAgentID != agentID {
		return refused(errors.New("revocation health receipt does not match the selected agent"))
	}
	if len(evidenceDigest) != 64 {
		return refused(errors.New("revocation health receipt has no SHA-256 evidence digest"))
	}
	for _, r := range evidenceDigest {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return refused(errors.New("revocation health receipt evidence digest is not lowercase hexadecimal"))
		}
	}
	// The digest names the exact findings document the receipt covers.
	if evidenceDigest != crypto.SHA256Hex([]byte(reportJSON)) {
		return refused(errors.New("revocation health evidence digest does not name the reported findings"))
	}
	var report revocationhealth.Report
	if err := decodeStrictJSON([]byte(reportJSON), &report); err != nil {
		return refused(fmt.Errorf("decode revocation health report: %w", err))
	}
	if err := revocationhealth.ValidateReport(intent, report); err != nil {
		return refused(err)
	}
	observed := revocationhealth.Observed{
		ProbeID: intent.ID, Bucket: intent.Bucket, BatchIndex: intent.BatchIndex,
		BatchCount: intent.BatchCount, AgentID: agentID, AgentName: agentName,
		EvidenceDigest: evidenceDigest, Targets: intent.Targets, Findings: report.Findings,
	}
	return s.orch.RecordRevocationHealthObservedWithEventID(ctx, tenantID,
		orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "revocation-health-observed"), observed)
}
