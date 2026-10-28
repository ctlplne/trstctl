// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/sshtrustrollout"
	"trstctl.com/trstctl/internal/store"
)

// recordSSHTrustFleetResult is called only after the existing agent-channel
// signature and claim checks. A structured report can never select its host,
// job, attempt or reviewed public key independently of the durable claim.
func (a *agentService) recordSSHTrustFleetResult(ctx context.Context, info mtls.PeerCertInfo, claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest) error {
	if a.orch == nil {
		return errors.New("SSH trust result receiver is not configured")
	}
	command, err := sshtrustrollout.DecodeCommand(bytes.NewReader(claim.Payload))
	if err != nil {
		return err
	}
	if !agentHasRole(info.Roles, mtls.AgentRoleHost) || command.AgentID != sshtrustrollout.EnrolledAgentID(info.TenantID, info.CommonName) || claim.Destination != sshtrustrollout.Destination || claim.IdempotencyKey != orchestrator.SSHTrustFleetJobKey(command.RolloutID, command.AgentID) {
		return errors.New("SSH trust job is not bound to this enrolled host")
	}
	report, err := sshtrustrollout.DecodeReport([]byte(req.Detail))
	if err != nil {
		return err
	}
	if err := report.Validate(command, req.EvidenceDigest); err != nil {
		return err
	}
	if report.State == "verified" && req.Outcome != transport.JobOutcomeVerified {
		return errors.New("SSH trust completion needs a verified signed result")
	}
	if report.State != "verified" && req.Outcome != transport.JobOutcomeVerifyFailed && req.Outcome != transport.JobOutcomeFailed {
		return errors.New("SSH trust failure cannot claim a verified effect")
	}
	observed := projections.SSHTrustFleetObserved{JobID: req.JobID, Attempt: req.Attempt, Report: report, EvidenceDigest: req.EvidenceDigest, ReceiptStatement: string(jobReceiptStatement(info, req).Canonical()), ReceiptSignature: base64.StdEncoding.EncodeToString(req.Signature), SignerFingerprint: info.FingerprintSHA256}
	eventID := evidenceID("ssh-trust-fleet-result", info.TenantID, fmt.Sprintf("%s:attempt:%d", claim.IdempotencyKey, req.Attempt), req.JobID)
	return a.orch.RecordSSHTrustFleetObservation(ctx, info.TenantID, eventID, observed)
}
