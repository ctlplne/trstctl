// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"time"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var errWindowsLocalAccountReportRefused = errors.New("local Windows account signed report refused")

func (a *agentService) boundWindowsLocalInventory(ctx context.Context, tenantID, agentID, key string, raw []byte) (hostaccounts.InventoryIntent, error) {
	intent, err := hostaccounts.DecodeInventoryIntent(raw)
	if err != nil {
		return intent, err
	}
	if intent.AgentID != agentID || intent.TenantID != tenantID || key != "windows-local-inventory:"+intent.RunID || a.log == nil {
		return intent, errWindowsLocalAccountReportRefused
	}
	event, found, err := a.log.EventByID(ctx, intent.RunID)
	if err != nil {
		return intent, err
	}
	if !found || event.TenantID != tenantID || event.Type != projections.EventWindowsLocalAccountScanQueued || event.SchemaVersion != 1 {
		return intent, errWindowsLocalAccountReportRefused
	}
	var queued projections.WindowsLocalAccountScanQueued
	if json.Unmarshal(event.Data, &queued) != nil || queued.Intent != intent || queued.Intent.Validate() != nil {
		return intent, errWindowsLocalAccountReportRefused
	}
	return intent, nil
}
func (a *agentService) projectWindowsLocalInventoryClaim(ctx context.Context, job store.AgentJob, agentID string) ([]byte, error) {
	intent, err := a.boundWindowsLocalInventory(ctx, job.TenantID, agentID, job.IdempotencyKey, job.Payload)
	if err != nil {
		return nil, err
	}
	v, err := a.store.GetWindowsLocalAccountScan(ctx, job.TenantID, intent.RunID)
	if err != nil {
		return nil, err
	}
	if v.ReportDigest != "" || v.Status == "failed" {
		return nil, errWindowsLocalAccountReportRefused
	}
	return job.Payload, nil
}

func (a *agentService) ingestWindowsLocalInventory(ctx context.Context, info mtls.PeerCertInfo, agentID string, claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest) error {
	intent, err := a.boundWindowsLocalInventory(ctx, info.TenantID, agentID, claim.IdempotencyKey, claim.Payload)
	if err != nil {
		return errWindowsLocalAccountReportRefused
	}
	report, err := hostaccounts.DecodeInventoryReport([]byte(req.Detail))
	if err != nil || report.Validate(intent) != nil || req.Outcome != transport.JobOutcomeExecuted {
		return errWindowsLocalAccountReportRefused
	}
	raw, err := json.Marshal(report)
	if err != nil || req.EvidenceDigest != crypto.SHA256Hex(raw) {
		return errWindowsLocalAccountReportRefused
	}
	// Retain/reapply the original append before constructing another timestamp.
	id := uuid.NewSHA1(uuid.NameSpaceURL, []byte("trstctl/windows-local-inventory/observed/"+info.TenantID+"/"+intent.RunID)).String()
	retained, found, err := a.log.EventByID(ctx, id)
	if err != nil {
		return err
	}
	if found {
		var original projections.WindowsLocalAccountScanObserved
		if retained.TenantID != info.TenantID || retained.Type != projections.EventWindowsLocalAccountScanObserved || retained.SchemaVersion != 1 || json.Unmarshal(retained.Data, &original) != nil || original.JobID != req.JobID || original.Attempt != req.Attempt || original.EvidenceDigest != req.EvidenceDigest || original.SignerFingerprint != info.FingerprintSHA256 || original.ReceiptStatement != string(jobReceiptStatement(info, req).Canonical()) {
			return errWindowsLocalAccountReportRefused
		}
		return projections.New(a.store).Apply(ctx, retained)
	}
	v, err := a.store.GetWindowsLocalAccountScan(ctx, info.TenantID, intent.RunID)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if v.OutboxID == nil || *v.OutboxID != req.JobID || report.ObservedAt.Before(v.QueuedAt.Add(-5*time.Minute)) || report.ObservedAt.After(now.Add(5*time.Minute)) {
		return errWindowsLocalAccountReportRefused
	}

	value := projections.WindowsLocalAccountScanObserved{JobID: req.JobID, Attempt: req.Attempt, Report: report, EvidenceDigest: req.EvidenceDigest, ReceiptStatement: string(jobReceiptStatement(info, req).Canonical()), ReceiptSignature: base64.StdEncoding.EncodeToString(req.Signature), SignerFingerprint: info.FingerprintSHA256, At: now}
	return a.appendServiceDependentAgentEventID(ctx, info.TenantID, id, projections.EventWindowsLocalAccountScanObserved, value)
}
func (a *agentService) recordWindowsLocalInventoryFailure(ctx context.Context, info mtls.PeerCertInfo, agentID string, claim store.AgentJobResultClaim, req *transport.ReportJobResultRequest, reason string) error {
	intent, err := a.boundWindowsLocalInventory(ctx, info.TenantID, agentID, claim.IdempotencyKey, claim.Payload)
	if err != nil {
		return err
	}
	value := projections.WindowsLocalAccountScanFailed{RunID: intent.RunID, JobID: req.JobID, Attempt: req.Attempt, Reason: reason, ReceiptStatement: string(jobReceiptStatement(info, req).Canonical()), ReceiptSignature: base64.StdEncoding.EncodeToString(req.Signature), SignerFingerprint: info.FingerprintSHA256, At: time.Now().UTC().Truncate(time.Microsecond)}
	// The scan stores UUID source coordinates; the generic log ID is a NUID.
	// Fix this attempt's failure ID before append and reapply its original bytes.
	id := uuid.NewSHA1(uuid.NameSpaceURL, []byte(fmt.Sprintf("trstctl/windows-local-inventory/failed/%s/%s/%d/%d", info.TenantID, intent.RunID, req.JobID, req.Attempt))).String()
	retained, found, err := a.log.EventByID(ctx, id)
	if err != nil {
		return err
	}
	if found {
		var original projections.WindowsLocalAccountScanFailed
		if retained.TenantID != info.TenantID || retained.Type != projections.EventWindowsLocalAccountScanFailed || retained.SchemaVersion != 1 || json.Unmarshal(retained.Data, &original) != nil || original.RunID != intent.RunID || original.JobID != req.JobID || original.Attempt != req.Attempt || original.Reason != reason || original.ReceiptStatement != value.ReceiptStatement || original.SignerFingerprint != info.FingerprintSHA256 {
			return errWindowsLocalAccountReportRefused
		}
		return projections.New(a.store).Apply(ctx, retained)
	}
	return a.appendServiceDependentAgentEventID(ctx, info.TenantID, id, projections.EventWindowsLocalAccountScanFailed, value)
}
