// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/orchestrator"
)

type PQCRollbackLifecycleCandidate struct {
	TenantID               string
	IdentityID             string
	AssetID                string
	PredecessorFingerprint string
	EventSequence          uint64
}

// recoverPQCCertificateRollbackLifecycle completes a signed host rollback
// whose lifecycle append was interrupted by a crash. A later lifecycle event
// or changed CBOM asset fences off a stale receipt.
func (s *Server) recoverPQCCertificateRollbackLifecycle(ctx context.Context, candidates func() []PQCRollbackLifecycleCandidate) error {
	if candidates == nil {
		return nil
	}
	for _, candidate := range candidates() {
		if candidate.TenantID == "" || candidate.IdentityID == "" || candidate.AssetID == "" ||
			candidate.PredecessorFingerprint == "" || candidate.EventSequence == 0 {
			return errors.New("PQC rollback recovery candidate is incomplete")
		}
		var state orchestrator.State
		var version uint64
		if err := s.store.WithTenant(ctx, candidate.TenantID, func(tx pgx.Tx) error {
			identity, last, err := s.store.IdentityApprovalTargetTx(ctx, tx, candidate.TenantID, candidate.IdentityID, false)
			if err == nil {
				state, version = orchestrator.State(identity.Status), last
			}
			return err
		}); err != nil {
			return fmt.Errorf("PQC rollback recovery identity: %w", err)
		}
		if state == orchestrator.StateIssued || state != orchestrator.StateDeployed || version >= candidate.EventSequence {
			continue
		}
		assets, err := s.store.ListCryptoAssets(ctx, candidate.TenantID)
		if err != nil {
			return err
		}
		restored := false
		for _, asset := range assets {
			if asset.ID == candidate.AssetID && strings.EqualFold(asset.CertificateFingerprint, candidate.PredecessorFingerprint) {
				restored = true
				break
			}
		}
		if !restored {
			continue
		}
		if err := s.orch.TransitionAfterVerifiedRollback(ctx, candidate.TenantID, candidate.IdentityID, version); err != nil {
			return fmt.Errorf("PQC rollback recovery lifecycle: %w", err)
		}
	}
	return nil
}

// completePQCCertificateRollbackLifecycle is called only after the signed
// predecessor readback has been durably projected. A lost job response may
// retry this step; an already-issued identity means it completed before.
func (s *Server) completePQCCertificateRollbackLifecycle(ctx context.Context, tenantID string, payload []byte) error {
	if s.orch == nil {
		return errors.New("PQC rollback lifecycle is unavailable")
	}
	var intent relay.RollbackIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		return err
	}
	if intent.PQCRunID == "" || intent.PQCAssetID == "" || intent.IdentityID == "" {
		return errors.New("PQC rollback lifecycle intent is incomplete")
	}
	state, err := s.orch.State(ctx, tenantID, intent.IdentityID)
	if err != nil {
		return err
	}
	if state == orchestrator.StateIssued {
		return nil
	}
	if state != orchestrator.StateDeployed {
		return errors.New("PQC rollback lifecycle changed while the host restored the predecessor")
	}
	return s.orch.TransitionAfterVerifiedRollback(ctx, tenantID, intent.IdentityID)
}
