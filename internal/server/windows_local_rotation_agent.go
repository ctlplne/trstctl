// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func (a *agentService) boundWindowsLocalRotation(ctx context.Context, tenantID, agentID, key string, raw []byte) (hostaccounts.RotationIntent, error) {
	i, e := hostaccounts.DecodeRotationIntent(raw)
	if e != nil {
		return i, e
	}
	if i.TenantID != tenantID || i.AgentID != agentID {
		return i, errors.New("native local rotation has another host")
	}
	v, cmd, e := projections.CanonicalWindowsLocalRotation(ctx, a.store, a.log, tenantID, i.RotationID)
	if e != nil {
		return i, e
	}
	if v.Intent != i || key != store.WindowsLocalRotationOutboxKey(cmd.TenantEpoch, i.RotationID) || cmd.Terminal() || cmd.Phase != store.SecretStaticRotationPrepared || v.Observation != nil && v.Observation.Report.Status == "succeeded" {
		return i, errors.New("native local rotation has no active exact generation")
	}
	return i, nil
}
func (a *agentService) projectWindowsLocalRotationClaim(ctx context.Context, job store.AgentJob, agentID string) ([]byte, error) {
	i, e := a.boundWindowsLocalRotation(ctx, job.TenantID, agentID, job.IdempotencyKey, job.Payload)
	if e != nil {
		return nil, e
	}
	v, e := a.store.GetWindowsLocalRotation(ctx, job.TenantID, i.RotationID)
	if e != nil {
		return nil, e
	}
	if v.OutboxID == nil || *v.OutboxID != job.ID {
		return nil, errors.New("native local rotation delivery differs")
	}
	return job.Payload, nil
}
func (a *agentService) ingestWindowsLocalRotation(ctx context.Context, info mtls.PeerCertInfo, agentID string, claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest) error {
	// Retained reports can replay their exact bytes after publication. Fresh
	// reports must still hold the prepared command's exact native authority.
	id := hostaccounts.RotationObservationSourceID(info.TenantID, req.JobID, req.Attempt)
	if source, found, e := a.log.EventByID(ctx, id); e != nil {
		return e
	} else if found {
		var saved projections.WindowsLocalRotationObserved
		if source.TenantID != info.TenantID || source.Type != projections.EventWindowsLocalRotationObserved || json.Unmarshal(source.Data, &saved) != nil || saved.JobID != req.JobID || saved.Attempt != req.Attempt || saved.EvidenceDigest != req.EvidenceDigest || saved.SignerFingerprint != info.FingerprintSHA256 || saved.ReceiptStatement != string(jobReceiptStatement(info, req).Canonical()) {
			return errors.New("native retained report differs")
		}
		return projections.New(a.store).Apply(ctx, source)
	}
	if !agentHasRole(info.Roles, mtls.AgentRoleHost) {
		return errors.New("native local report requires host role")
	}
	i, e := a.boundWindowsLocalRotation(ctx, info.TenantID, agentID, claim.IdempotencyKey, claim.Payload)
	if e != nil {
		return e
	}
	report, e := hostaccounts.DecodeRotationReport([]byte(req.Detail))
	if e != nil || report.Validate(i) != nil || req.Outcome != transport.JobOutcomeExecuted {
		return errors.New("native local report differs from exact generation")
	}
	raw, e := json.Marshal(report)
	if e != nil || crypto.SHA256Hex(raw) != req.EvidenceDigest {
		return errors.New("native local report evidence differs")
	}
	v, e := a.store.GetWindowsLocalRotation(ctx, info.TenantID, i.RotationID)
	if e != nil {
		return e
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if v.OutboxID == nil || *v.OutboxID != req.JobID || !projections.ValidWindowsLocalRotationObservationTime(report.ObservedAt, v.PreparedAt, now) {
		return errors.New("native local report has another delivery or native observation time")
	}
	value := projections.WindowsLocalRotationObserved{JobID: req.JobID, Attempt: req.Attempt, Report: report, EvidenceDigest: req.EvidenceDigest, ReceiptStatement: string(jobReceiptStatement(info, req).Canonical()), ReceiptSignature: base64.StdEncoding.EncodeToString(req.Signature), SignerFingerprint: info.FingerprintSHA256, At: now}
	return a.appendServiceDependentAgentEventID(ctx, info.TenantID, id, projections.EventWindowsLocalRotationObserved, value)
}
func (r *relayCredentialResolver) resolveWindowsLocalRotation(ctx context.Context, tenantID string, job store.AgentJobForRedemption) (redeemedMaterial, error) {
	if r.windowsLocalRotationCredentials == nil {
		return redeemedMaterial{}, errors.New("native local credential broker is unavailable")
	}
	i, e := hostaccounts.DecodeRotationIntent(job.Payload)
	if e != nil {
		return redeemedMaterial{}, e
	}
	if i.TenantID != tenantID || i.AgentID != job.RequiredAgentID {
		return redeemedMaterial{}, errors.New("native local credential has another host")
	}
	old, next, e := r.windowsLocalRotationCredentials(ctx, tenantID, i, job.ID, job.ClaimAttempts)
	if e != nil {
		secret.Wipe(old)
		secret.Wipe(next)
		return redeemedMaterial{}, e
	}
	defer secret.Wipe(old)
	defer secret.Wipe(next)
	oldHeld, e := secret.NewFrom(old)
	if e != nil {
		return redeemedMaterial{}, e
	}
	nextHeld, e := secret.NewFrom(next)
	if e != nil {
		oldHeld.Destroy()
		return redeemedMaterial{}, e
	}
	names := []string{hostaccounts.RotationOldCredentialName, hostaccounts.RotationNewCredentialName}
	return redeemedMaterial{items: []transport.RedeemedSecret{{Name: names[0], Value: secret.JSONBytes(oldHeld.Bytes())}, {Name: names[1], Value: secret.JSONBytes(nextHeld.Bytes())}}, refNames: names, wipe: func() { oldHeld.Destroy(); nextHeld.Destroy() }}, nil
}
