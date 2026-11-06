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
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

var errServiceDependentRotationReportRefused = errors.New("native dependent rotation report was refused")

func (a *agentService) boundServiceDependentStep(ctx context.Context, tenantID, agentID, key string, raw []byte) (servicedependents.RotationStep, error) {
	step, e := servicedependents.DecodeRotationStep(raw)
	if e != nil {
		return step, e
	}
	if step.Ref.AgentID != agentID || key != "service-dependent-step:"+step.RotationID+":"+step.ID {
		return step, errors.New("native dependent step names another host or expired authority")
	}
	source, found, e := a.log.EventByID(ctx, servicedependents.StepSourceID(step.RotationID, step.ID))
	if e != nil {
		return step, e
	}
	var queued projections.ServiceDependentStepQueued
	if !found || source.TenantID != tenantID || source.Type != projections.EventServiceDependentStepQueued || json.Unmarshal(source.Data, &queued) != nil {
		return step, errors.New("native dependent step has no canonical queued source")
	}
	canonical, e := json.Marshal(queued.Step)
	if e != nil {
		return step, e
	}
	submitted, e := json.Marshal(step)
	if e != nil {
		return step, e
	}
	if crypto.SHA256Hex(canonical) != crypto.SHA256Hex(submitted) {
		return step, errors.New("native dependent step differs from its source")
	}
	parent, e := a.store.GetServiceDependentRotation(ctx, tenantID, step.RotationID)
	if e != nil {
		return step, e
	}
	parentSource, found, e := a.log.EventByID(ctx, parent.ID)
	if e != nil {
		return step, e
	}
	var authority projections.ServiceDependentRotationQueued
	if !found || parentSource.TenantID != tenantID || parentSource.Type != projections.EventServiceDependentRotationQueued || json.Unmarshal(parentSource.Data, &authority) != nil {
		return step, errors.New("native dependent step has no canonical parent")
	}
	digest, e := authority.Intent.Digest()
	if e != nil || digest != step.PlanDigest || digest != parent.IntentDigest {
		return step, errors.New("native parent intent differs")
	}
	inverse, hasInverse, e := a.log.EventByID(ctx, servicedependents.InverseSourceID(parent.ID))
	if e != nil {
		return step, e
	}
	direction := servicedependents.Forward
	if hasInverse {
		var selected projections.ServiceDependentRotationInverse
		if inverse.TenantID != tenantID || inverse.Type != projections.EventServiceDependentRotationInverse || json.Unmarshal(inverse.Data, &selected) != nil || selected.RotationID != parent.ID || selected.IntentDigest != digest {
			return step, errors.New("native inverse source differs")
		}
		direction = servicedependents.Inverse
	}
	if step.Direction != direction || parent.Direction != direction {
		return step, errors.New("native dependent direction was superseded")
	}
	if direction == servicedependents.Inverse {
		restored, found, e := a.log.EventByID(ctx, servicedependents.DirectoryRestoredSourceID(parent.ID))
		if e != nil {
			return step, e
		}
		var proof projections.ServiceDependentDirectoryRestored
		if !found || restored.TenantID != tenantID || restored.Type != projections.EventServiceDependentDirectoryRestored || json.Unmarshal(restored.Data, &proof) != nil || proof.RotationID != parent.ID || proof.IntentDigest != digest || !parent.DirectoryRestored {
			return step, errors.New("native dependent inverse precedes directory recovery")
		}
	}
	child, e := a.store.GetSecretStaticRotationCommand(ctx, tenantID, parent.CommandID)
	if e != nil {
		return step, e
	}
	if child.DependentChangeID != parent.ID || child.RequestBinding != digest || child.ID != authority.Child.ID {
		return step, errors.New("native dependent child authority differs")
	}
	if direction == servicedependents.Forward {
		if step.Action == servicedependents.Preflight && child.Phase != store.SecretStaticRotationPrepared || step.Action != servicedependents.Preflight && child.Phase != store.SecretStaticRotationStaged {
			return step, errors.New("native forward step is outside the current directory phase")
		}
	} else if child.Phase != store.SecretStaticRotationPrepared && child.Phase != store.SecretStaticRotationStaged && child.Phase != store.SecretStaticRotationCutover {
		return step, errors.New("native inverse step is outside the current recovery phase")
	}
	return step, nil
}
func (a *agentService) projectServiceDependentRotationClaim(ctx context.Context, job store.AgentJob, agentID string) ([]byte, error) {

	step, e := a.boundServiceDependentStep(ctx, job.TenantID, agentID, job.IdempotencyKey, job.Payload)
	if e != nil {
		return nil, e
	}
	saved, e := a.store.GetServiceDependentStep(ctx, job.TenantID, step.RotationID, step.ID)
	if e != nil {
		return nil, e
	}
	_, observed, e := a.log.EventByID(ctx, servicedependents.StepObservedSourceID(step.RotationID, step.ID))
	if e != nil {
		return nil, e
	}
	if observed {
		return nil, errors.New("native dependent work already has a canonical observation")
	}
	if !time.Now().Before(step.Deadline) {
		return nil, errors.New("native dependent execution lease expired")
	}
	if saved.Status != "queued" || saved.OutboxID == nil || *saved.OutboxID != job.ID {
		return nil, errors.New("native dependent job was already observed or replaced")
	}
	return job.Payload, nil
}
func (a *agentService) ingestServiceDependentRotation(ctx context.Context, info mtls.PeerCertInfo, agentID string, claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest) error {
	step, e := a.boundServiceDependentStep(ctx, info.TenantID, agentID, claim.IdempotencyKey, claim.Payload)
	if e != nil {
		return errServiceDependentRotationReportRefused
	}
	if req.Outcome != transport.JobOutcomeExecuted && req.Outcome != transport.JobOutcomeFailed {
		return errServiceDependentRotationReportRefused
	}
	report, e := servicedependents.DecodeStepReport([]byte(req.Detail))
	if req.Outcome == transport.JobOutcomeExecuted && report.Status != "succeeded" || req.Outcome == transport.JobOutcomeFailed && report.Status == "succeeded" {
		return errServiceDependentRotationReportRefused
	}
	if e != nil || report.Validate(step) != nil {
		return errServiceDependentRotationReportRefused
	}
	raw, e := json.Marshal(report)
	if e != nil || crypto.SHA256Hex(raw) != req.EvidenceDigest {
		return errServiceDependentRotationReportRefused
	}
	saved, e := a.store.GetServiceDependentStep(ctx, info.TenantID, step.RotationID, step.ID)
	if e != nil {
		return e
	}
	if saved.OutboxID == nil || *saved.OutboxID != req.JobID {
		return errServiceDependentRotationReportRefused
	}
	value := projections.ServiceDependentStepObserved{Report: report, JobID: req.JobID, Attempt: req.Attempt, ReceiptStatement: string(jobReceiptStatement(info, req).Canonical()), ReceiptSignature: base64.StdEncoding.EncodeToString(req.Signature), SignerFingerprint: info.FingerprintSHA256, At: time.Now().UTC()}
	return a.appendServiceDependentAgentEventID(ctx, info.TenantID, servicedependents.StepObservedSourceID(step.RotationID, step.ID), projections.EventServiceDependentStepObserved, value)
}
func (r *relayCredentialResolver) resolveServiceDependentRotation(ctx context.Context, tenantID string, job store.AgentJobForRedemption) (redeemedMaterial, error) {
	if r.dependentRotationCredential == nil {
		return redeemedMaterial{}, errors.New("native dependent credential resolver unavailable")
	}
	step, e := servicedependents.DecodeRotationStep(job.Payload)
	if e != nil {
		return redeemedMaterial{}, e
	}
	if step.Ref.AgentID != job.RequiredAgentID || step.Action != servicedependents.Update {
		return redeemedMaterial{}, errors.New("native dependent credential has another host or operation")
	}
	password, e := r.dependentRotationCredential(ctx, tenantID, step)
	if e != nil {
		return redeemedMaterial{}, e
	}
	held, e := secret.NewFrom(password)
	secret.Wipe(password)
	if e != nil {
		return redeemedMaterial{}, e
	}
	return redeemedMaterial{items: []transport.RedeemedSecret{{Name: servicedependents.RotationCredentialName, Value: secret.JSONBytes(held.Bytes())}}, refNames: []string{servicedependents.RotationCredentialName}, wipe: held.Destroy}, nil
}
