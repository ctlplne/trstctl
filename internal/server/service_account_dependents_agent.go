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
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

var errServiceDependentReportRefused = errors.New("service dependent signed native report was refused")

// A derived row alone cannot authorize even a native read. The queued source
// binds the directory object, exact enrolled host, revision and operation.
func (a *agentService) projectServiceDependentInventoryClaim(ctx context.Context, job store.AgentJob, agentID string) ([]byte, error) {
	intent, err := servicedependents.DecodeInventoryIntent(job.Payload)
	if err != nil {
		return nil, err
	}
	if agentID == "" || agentID != intent.Binding.AgentID {
		return nil, errors.New("native inventory source names another enrolled host")
	}
	if a.log == nil || job.IdempotencyKey != "service-dependent-inventory:"+intent.RunID {
		return nil, errors.New("native inventory has no matching queued source")
	}
	event, found, err := a.log.EventByID(ctx, intent.RunID)
	if err != nil {
		return nil, err
	}
	if !found || event.TenantID != job.TenantID || event.Type != projections.EventServiceDependentScanQueued || event.SchemaVersion != 1 {
		return nil, errors.New("native inventory source differs")
	}
	var queued projections.ServiceDependentScanQueued
	if json.Unmarshal(event.Data, &queued) != nil || queued.Intent.Validate() != nil || queued.Intent.RunID != intent.RunID || queued.Intent.BindingDigest != intent.BindingDigest {
		return nil, errors.New("native inventory source authority differs")
	}
	host, err := a.store.GetServiceDependentHost(ctx, job.TenantID, intent.Binding.Account.AccountID, intent.Binding.AgentID)
	if err != nil {
		return nil, err
	}
	digest, err := host.Binding.Digest()
	if err != nil || digest != intent.BindingDigest || !host.Binding.Enabled {
		return nil, errors.New("native inventory binding was superseded")
	}
	return job.Payload, nil
}
func (a *agentService) ingestServiceDependentInventory(ctx context.Context, info mtls.PeerCertInfo, agentID string, claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest) error {
	if req.Outcome != transport.JobOutcomeExecuted {
		return errServiceDependentReportRefused
	}
	intent, err := servicedependents.DecodeInventoryIntent(claim.Payload)
	if err != nil {
		return errServiceDependentReportRefused
	}
	if intent.Binding.AgentID != agentID {
		return errServiceDependentReportRefused
	}
	report, err := servicedependents.DecodeInventoryReport([]byte(req.Detail))
	if err != nil {
		return errServiceDependentReportRefused
	}
	if err := report.Validate(intent); err != nil {
		return errServiceDependentReportRefused
	}
	raw, err := json.Marshal(report)
	if err != nil || req.EvidenceDigest != crypto.SHA256Hex(raw) {
		return errServiceDependentReportRefused
	}
	now := time.Now().UTC()
	scan, err := a.store.GetServiceDependentScan(ctx, info.TenantID, intent.RunID)
	if err != nil {
		return err
	}
	if scan.OutboxID == nil || *scan.OutboxID != req.JobID || report.ObservedAt.Before(scan.QueuedAt.Add(-5*time.Minute)) || report.ObservedAt.After(now.Add(5*time.Minute)) {
		return errServiceDependentReportRefused
	}
	if scan.ReportDigest != "" {
		if scan.ReportDigest != req.EvidenceDigest || scan.Attempt == nil || *scan.Attempt != req.Attempt || scan.ReceiptJobID == nil || *scan.ReceiptJobID != req.JobID {
			return errServiceDependentReportRefused
		}
		return nil
	}
	value := projections.ServiceDependentScanObserved{JobID: req.JobID, Attempt: req.Attempt, Report: report, EvidenceDigest: req.EvidenceDigest, ReceiptStatement: string(jobReceiptStatement(info, req).Canonical()), ReceiptSignature: base64.StdEncoding.EncodeToString(req.Signature), SignerFingerprint: info.FingerprintSHA256, At: now}
	return a.appendServiceDependentAgentEvent(ctx, info.TenantID, projections.EventServiceDependentScanObserved, value)
}
func (a *agentService) recordServiceDependentFailure(ctx context.Context, info mtls.PeerCertInfo, claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest, reason string) error {
	intent, err := servicedependents.DecodeInventoryIntent(claim.Payload)
	if err != nil {
		return err
	}
	value := projections.ServiceDependentScanFailed{RunID: intent.RunID, JobID: req.JobID, Attempt: req.Attempt, Reason: reason, ReceiptStatement: string(jobReceiptStatement(info, req).Canonical()), ReceiptSignature: base64.StdEncoding.EncodeToString(req.Signature), SignerFingerprint: info.FingerprintSHA256, At: time.Now().UTC()}
	return a.appendServiceDependentAgentEvent(ctx, info.TenantID, projections.EventServiceDependentScanFailed, value)
}
func (a *agentService) appendServiceDependentAgentEvent(ctx context.Context, tenantID, kind string, value any) error {
	return a.appendServiceDependentAgentEventID(ctx, tenantID, "", kind, value)
}
func (a *agentService) appendServiceDependentAgentEventID(ctx context.Context, tenantID, eventID, kind string, value any) error {
	if a.log == nil || a.store == nil {
		return errors.New("native inventory event receiver is unavailable")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	event, err := a.log.Append(ctx, events.Event{ID: eventID, TenantID: tenantID, Type: kind, Data: raw, SchemaVersion: 1})
	if err != nil {
		return err
	}
	return projections.New(a.store).Apply(ctx, event)
}
