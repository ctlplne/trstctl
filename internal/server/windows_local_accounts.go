// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/hostaccounts"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func (s *pamService) windowsLocalAccountHost(ctx context.Context, tenantID, agentID string) error {
	if !validUUID(agentID) {
		return store.ErrWindowsLocalAccountScanNotFound
	}
	host, err := s.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return store.ErrWindowsLocalAccountScanNotFound
	}
	if host.OffboardedAt != nil || !slices.Contains(host.Roles, mtls.AgentRoleHost) {
		return fmt.Errorf("%w: an active enrolled host role is required", api.ErrPAMInvalid)
	}
	return nil
}
func (s *pamService) RunPAMWindowsLocalAccountInventory(ctx context.Context, tenantID, actor, agentID, runID string) (store.WindowsLocalAccountScan, error) {
	var result store.WindowsLocalAccountScan
	if actor == "" || !validUUID(runID) {
		return result, fmt.Errorf("%w: an authenticated author is required", api.ErrPAMInvalid)
	}
	if err := s.windowsLocalAccountHost(ctx, tenantID, agentID); err != nil {
		return result, err
	}
	if !s.windowsLocalAccountInventoryEnabled {
		return result, fmt.Errorf("%w: enable host.windows_local_accounts.inventory in agent.claimable_job_kinds", api.ErrPAMInvalid)
	}
	err := s.store.WithPAMCatalogLock(ctx, tenantID, func() error {
		if err := s.windowsLocalAccountHost(ctx, tenantID, agentID); err != nil {
			return err
		}
		retained, found, err := s.log.EventByID(ctx, runID)
		if err != nil {
			return err
		}
		if found {
			var queued projections.WindowsLocalAccountScanQueued
			if retained.TenantID != tenantID || retained.Type != projections.EventWindowsLocalAccountScanQueued || retained.SchemaVersion != 1 || json.Unmarshal(retained.Data, &queued) != nil || queued.Intent.Validate() != nil || queued.Intent.RunID != runID || queued.Intent.TenantID != tenantID || queued.Intent.AgentID != agentID || queued.Actor != actor {
				return store.ErrIdempotencyConflict
			}
			if err := s.projector.Apply(ctx, retained); err != nil {
				return err
			}
			result, err = s.store.GetWindowsLocalAccountScan(ctx, tenantID, runID)
			return err
		}
		if pending, err := s.store.PendingWindowsLocalAccountScan(ctx, tenantID, agentID); err != nil {
			return err
		} else if pending {
			return fmt.Errorf("%w: this host already has a queued inventory read", api.ErrPAMTargetConflict)
		}
		provider := store.WindowsHostAccountProviderID(agentID)
		if src, err := s.store.GetPAMDiscoverySource(ctx, tenantID, provider); err == nil && src.ProviderType != "windows_local" {
			return fmt.Errorf("%w: enrolled-host discovery source name is already in use", api.ErrPAMTargetConflict)
		} else if err != nil && !errors.Is(err, store.ErrPAMDiscoverySourceNotFound) {
			return err
		}
		intent, err := hostaccounts.NewInventoryIntent(runID, tenantID, agentID)
		if err != nil {
			return err
		}
		value := projections.WindowsLocalAccountScanQueued{Intent: intent, Actor: actor, At: s.clock().UTC().Truncate(time.Microsecond)}
		if err := s.appendServiceDependentEvent(ctx, tenantID, intent.RunID, projections.EventWindowsLocalAccountScanQueued, value); err != nil {
			return err
		}
		result, err = s.store.GetWindowsLocalAccountScan(ctx, tenantID, intent.RunID)
		return err
	})
	if err == nil && s.wakeOutbox != nil {
		s.wakeOutbox()
	}
	return result, err
}
func (s *pamService) GetPAMWindowsLocalAccountScan(ctx context.Context, tenantID, agentID, id string) (store.WindowsLocalAccountScan, error) {
	if !validUUID(agentID) || !validUUID(id) {
		return store.WindowsLocalAccountScan{}, store.ErrWindowsLocalAccountScanNotFound
	}
	v, err := s.store.GetWindowsLocalAccountScan(ctx, tenantID, id)
	if err == nil && v.Intent.AgentID != agentID {
		return store.WindowsLocalAccountScan{}, store.ErrWindowsLocalAccountScanNotFound
	}
	if err == nil {
		err = s.canonicalWindowsLocalAccountScan(ctx, tenantID, v, false)
	}
	return v, err
}
func (s *pamService) ListPAMWindowsLocalAccountScans(ctx context.Context, tenantID, agentID, after string, limit int) (api.PAMWindowsLocalAccountScanList, error) {
	result := api.PAMWindowsLocalAccountScanList{Items: []store.WindowsLocalAccountScan{}}
	if err := s.windowsLocalAccountHost(ctx, tenantID, agentID); err != nil {
		return result, err
	}
	if after == "" {
		after = store.ZeroUUID
	} else if !validUUID(after) {
		return result, fmt.Errorf("%w: after must be a scan UUID", api.ErrPAMInvalid)
	}
	if limit < 1 || limit > 100 {
		return result, fmt.Errorf("%w: limit must be 1-100", api.ErrPAMInvalid)
	}
	items, err := s.store.ListWindowsLocalAccountScans(ctx, tenantID, agentID, after, limit)
	if err != nil {
		return result, err
	}
	if len(items) > limit {
		items = items[:limit]
		result.NextCursor = items[len(items)-1].ID
	}
	for _, item := range items {
		if err := s.canonicalWindowsLocalAccountScan(ctx, tenantID, item, true); err != nil {
			return result, err
		}
	}
	result.Items = append(result.Items, items...)
	return result, nil
}
func (s *Server) RunPAMWindowsLocalAccountInventory(ctx context.Context, t, a, h, id string) (store.WindowsLocalAccountScan, error) {
	if s.pam == nil {
		return store.WindowsLocalAccountScan{}, api.ErrPAMUnavailable
	}
	return s.pam.RunPAMWindowsLocalAccountInventory(ctx, t, a, h, id)
}
func (s *Server) GetPAMWindowsLocalAccountScan(ctx context.Context, t, h, id string) (store.WindowsLocalAccountScan, error) {
	if s.pam == nil {
		return store.WindowsLocalAccountScan{}, api.ErrPAMUnavailable
	}
	return s.pam.GetPAMWindowsLocalAccountScan(ctx, t, h, id)
}
func (s *Server) ListPAMWindowsLocalAccountScans(ctx context.Context, t, h, c string, n int) (api.PAMWindowsLocalAccountScanList, error) {
	if s.pam == nil {
		return api.PAMWindowsLocalAccountScanList{}, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMWindowsLocalAccountScans(ctx, t, h, c, n)
}

// A SQL cache cannot turn a queued read into signed native authority. Reopen
// the retained source before exposing completion or using it for later rotation.
func (s *pamService) canonicalWindowsLocalAccountScan(ctx context.Context, tenantID string, v store.WindowsLocalAccountScan, summary bool) error {
	if s.log == nil || v.QueuedEventID != v.ID || v.Intent.TenantID != tenantID {
		return errors.New("local inventory source unavailable")
	}
	source, found, err := s.log.EventByID(ctx, v.QueuedEventID)
	if err != nil {
		return err
	}
	var q projections.WindowsLocalAccountScanQueued
	if !found || source.TenantID != tenantID || source.Type != projections.EventWindowsLocalAccountScanQueued || source.SchemaVersion != 1 || json.Unmarshal(source.Data, &q) != nil || q.Intent != v.Intent || q.Intent.Validate() != nil || q.Actor != v.QueuedBy || !q.At.Equal(v.QueuedAt) {
		return errors.New("local inventory queued source differs")
	}
	if v.ObservedEventID == "" {
		if v.Status != "queued" || v.ReportDigest != "" || v.Report != nil || v.ReceiptJobID != nil {
			return errors.New("local inventory completion has no retained source")
		}
		return nil
	}
	observed, found, err := s.log.EventByID(ctx, v.ObservedEventID)
	if err != nil {
		return err
	}
	if !found || observed.TenantID != tenantID || observed.SchemaVersion != 1 || observed.Sequence <= source.Sequence {
		return errors.New("local inventory observation source differs")
	}
	receiptMatches := func(jobID int64, attempt int, statement, signature, fingerprint string, at time.Time) bool {
		return v.ReceiptJobID != nil && *v.ReceiptJobID == jobID && v.Attempt != nil && *v.Attempt == attempt && v.ReceiptStatement == statement && v.ReceiptSignature == signature && v.SignerFingerprint == fingerprint && v.ReceivedAt != nil && v.ReceivedAt.Equal(at)
	}
	switch observed.Type {
	case projections.EventWindowsLocalAccountScanObserved:
		var value projections.WindowsLocalAccountScanObserved
		if json.Unmarshal(observed.Data, &value) != nil || value.Report.Validate(v.Intent) != nil || !receiptMatches(value.JobID, value.Attempt, value.ReceiptStatement, value.ReceiptSignature, value.SignerFingerprint, value.At) {
			return errors.New("local inventory signed observation differs")
		}
		raw, err := json.Marshal(value.Report)
		if err != nil || crypto.SHA256Hex(raw) != value.EvidenceDigest || value.EvidenceDigest != v.ReportDigest || v.Failure != value.Report.Failure {
			return errors.New("local inventory native report differs")
		}
		state := "failed"
		if value.Report.Status == "complete" {
			state = "complete"
		}
		if v.Status != state {
			return errors.New("local inventory completion state differs")
		}
		if !summary {
			if v.Report == nil {
				return errors.New("local inventory report is missing")
			}
			raw, err = json.Marshal(v.Report)
			if err != nil || crypto.SHA256Hex(raw) != value.EvidenceDigest {
				return errors.New("local inventory cached native report differs")
			}
		}
	case projections.EventWindowsLocalAccountScanFailed:
		var value projections.WindowsLocalAccountScanFailed
		if json.Unmarshal(observed.Data, &value) != nil || value.RunID != v.ID || !receiptMatches(value.JobID, value.Attempt, value.ReceiptStatement, value.ReceiptSignature, value.SignerFingerprint, value.At) || v.ReportDigest != "" || v.Report != nil || v.Failure != value.Reason {
			return errors.New("local inventory failure source differs")
		}
		state := "retrying"
		if value.Reason == "invalid_native_report" {
			state = "failed"
		} else if value.Reason != "agent_execution_failed" {
			return errors.New("local inventory failure class differs")
		}
		if v.Status != state {
			return errors.New("local inventory failed state differs")
		}
	default:
		return errors.New("local inventory result source type differs")
	}
	return nil
}
