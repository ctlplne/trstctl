// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/historycontinuity"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// openHistoryAwareEventLog is the production event-log constructor. A restart
// can discover an activated-but-not-yet-scrubbed generation switch during Open,
// so both the deployment-wide PostgreSQL coordinator and the persistent-key
// receipt verifier must exist before events.Open begins recovery.
func openHistoryAwareEventLog(
	ctx context.Context,
	cfg config.NATS,
	st *store.Store,
	auditKey *jose.SigningKey,
) (*events.Log, error) {
	if st == nil {
		return nil, errors.New("server: history-aware event log requires a store")
	}
	if auditKey == nil {
		return nil, errors.New("server: history-aware event log requires the persistent audit signing key")
	}
	return events.Open(
		ctx,
		cfg,
		events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(st)),
		events.WithHistoryRewriteContinuityVerifier(historycontinuity.NewReceiptVerifier(auditKey)),
	)
}

// historyRewriteOrchestratorOptions wires the proof callbacks that are invoked by
// the served privacy erasure command. The privacy transform owns its specialized
// actor/data pair validator inside events.PseudonymizeSubject; the three options
// here supply the external trust walls it cannot own itself.
func historyRewriteOrchestratorOptions(
	st *store.Store,
	auditKey *jose.SigningKey,
) []orchestrator.OrchestratorOption {
	proof := historyRewriteProofOptions(st, auditKey)
	if len(proof) == 0 {
		return nil
	}
	return []orchestrator.OrchestratorOption{
		orchestrator.WithTenantDataRewriteOptions(proof...),
	}
}

// historyRewriteProofOptions is the one production proof chain shared by every
// served tenant-data generation switch. Privacy erasure and tenant-domain
// migration must not drift onto different backup, audit, or signing walls.
func historyRewriteProofOptions(
	st *store.Store,
	auditKey *jose.SigningKey,
) []events.TenantDataRewriteOption {
	if st == nil || auditKey == nil {
		return nil
	}
	return []events.TenantDataRewriteOption{
		events.WithTenantDataContinuity(historycontinuity.NewReceiptSigner(auditKey)),
		events.WithTenantDataCutoverPreparation(st.PrepareTenantDataCutover),
		events.WithTenantDataAuditContinuity(historycontinuity.AuditCheckpointProvider(st)),
	}
}
