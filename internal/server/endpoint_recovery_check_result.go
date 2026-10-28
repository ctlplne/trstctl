// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// recordEndpointRecoveryCheckResult projects a host's signed recovery check
// onto the request it answers (A210). A retry of the same report reuses the
// same event id and cannot change the answer.
func (a *agentService) recordEndpointRecoveryCheckResult(ctx context.Context, info mtls.PeerCertInfo,
	claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest) error {
	if a.orch == nil {
		return errors.New("recovery check receiver is unavailable")
	}
	if req.Outcome != transport.JobOutcomeExecuted {
		return errors.New("recovery check result needs a terminal executed report")
	}
	var intent relay.RecoveryCheckIntent
	var result relay.RecoveryCheckReport
	if err := decodeStrictJSON(claim.Payload, &intent); err != nil {
		return err
	}
	if err := decodeStrictJSON([]byte(req.Detail), &result); err != nil {
		return err
	}
	if err := relay.ValidateRecoveryCheckReport(intent, result, req.EvidenceDigest); err != nil {
		return err
	}
	serving := ""
	if result.Probe != nil && result.Probe.Reached {
		serving = strings.ToLower(result.Probe.ObservedFingerprint)
	}
	return a.orch.RecordEndpointRecoveryCheck(ctx, info.TenantID,
		evidenceID("endpoint-recovery-check-result", info.TenantID,
			fmt.Sprintf("%s:attempt:%d", claim.IdempotencyKey, req.Attempt), req.JobID),
		projections.EndpointRecoveryChecked{
			CheckID: intent.CheckID, TargetID: intent.TargetID, JobID: req.JobID, Attempt: req.Attempt,
			Recovery: result.Recovery, RecoveryAction: result.RecoveryAction,
			ExecutableSHA256: result.ExecutableSHA256, ArgvSHA256: result.ArgvSHA256,
			Listener: result.Listener, ServingFingerprint: serving, EvidenceDigest: req.EvidenceDigest,
			ReceiptStatement:  string(jobReceiptStatement(info, req).Canonical()),
			ReceiptSignature:  base64.StdEncoding.EncodeToString(req.Signature),
			SignerFingerprint: info.FingerprintSHA256, Agent: info.CommonName,
		})
}

// recordEndpointRecoveryCheckFailure records a host's signed refusal with a
// closed reason; no agent-supplied text reaches the event log.
func (a *agentService) recordEndpointRecoveryCheckFailure(ctx context.Context, info mtls.PeerCertInfo,
	claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest) error {
	if a.orch == nil {
		return errors.New("recovery check receiver is unavailable")
	}
	var intent relay.RecoveryCheckIntent
	if err := json.Unmarshal(claim.Payload, &intent); err != nil || intent.CheckID == "" || intent.TargetID == "" {
		return errors.New("recovery check failure has no queued check")
	}
	reason := "the host could not complete the recovery check; inspect the signed job receipt and host profile"
	switch strings.TrimSpace(req.Detail) {
	case "recovery check intent is invalid":
		reason = "the host rejected the queued recovery check"
	case "host profile's recovery action is not one of its actions":
		reason = "the host profile's recovery action is not one of its actions"
	case "host profile's recovery executable could not be read":
		reason = "the host could not read the recovery action's executable"
	case "recovery check probe could not run":
		reason = "the host could not probe the listener"
	}
	return a.orch.RecordEndpointRecoveryCheckFailure(ctx, info.TenantID,
		evidenceID("endpoint-recovery-check-failure", info.TenantID,
			fmt.Sprintf("%s:attempt:%d", claim.IdempotencyKey, req.Attempt), req.JobID),
		projections.EndpointRecoveryCheckFailed{
			CheckID: intent.CheckID, TargetID: intent.TargetID, JobID: req.JobID, Attempt: req.Attempt,
			Reason: reason, ReceiptSignature: base64.StdEncoding.EncodeToString(req.Signature),
			SignerFingerprint: info.FingerprintSHA256, Agent: info.CommonName,
		})
}
