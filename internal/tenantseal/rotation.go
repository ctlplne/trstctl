// SPDX-License-Identifier: BUSL-1.1

package tenantseal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Rotate moves a migrated tenant domain to its next generation: a fresh domain
// KEK under the same or another configured wrapper, every hot-state container
// and the tenant's event history re-wrapped from generation g to g+1 without
// opening a payload, then the new generation promoted. An empty ref keeps the
// current wrapper. Until the promotion commits both generations stay readable,
// so a crash or failure leaves a rotation that a retry resumes with the same
// target. Only data keys are re-wrapped; payload ciphertext is unchanged, so
// copies taken before the rotation (backups, archives, exports) still open
// with generation g, whose wrapped KEK stays in the event history.
func (l *Lifecycle) Rotate(
	ctx context.Context,
	tenantID string,
	ref WrapperRef,
) (store.TenantKeyDomain, error) {
	if err := l.validateRotationPreconditions(tenantID, ref); err != nil {
		return store.TenantKeyDomain{}, err
	}
	var out store.TenantKeyDomain
	err := l.log.WithHistoryOperation(ctx, func(operationCtx context.Context) error {
		domain, keys, err := l.beginOrResumeRotation(operationCtx, tenantID, ref)
		if err != nil {
			return err
		}
		defer keys.destroy()
		rewriter, err := NewRotationRewrapper(keys.current, keys.sourceBinding, keys.next, keys.targetBinding)
		if err != nil {
			return l.failRotation(operationCtx, domain, "rewrapper_unavailable", "tenant ciphertext rewrapper is unavailable", err)
		}

		stages := store.TenantKeyDomainCiphertextMigrationStages()
		for index, stage := range stages {
			if _, err := l.store.RewriteTenantKeyDomainCiphertextStage(
				operationCtx, tenantID, stage,
				func(before []byte) ([]byte, bool, error) {
					return rewriter.Transform("postgres."+stage, 1, before)
				},
			); err != nil {
				return l.failRotation(operationCtx, domain, "hot_state_rewrap_failed", "tenant hot-state rewrap failed", err)
			}
			domain.ProgressCompleted = int64(index + 1)
			domain.ProgressCursor = stage
			domain.MigrationStage = stage
			domain.OperationStatus = store.TenantKeyOperationRunning
			domain.Retryable = true
			domain.LastErrorCode, domain.LastError = "", ""
			if err := l.appendSnapshot(operationCtx, tenantID, projections.EventTenantKeyDomainRotationProgressed, domain); err != nil {
				return err
			}
		}

		historyOptions := append(
			[]events.TenantDataRewriteOption{
				events.WithTenantDataPairValidator(rewriter.ValidatePair),
			},
			l.rewriteOptions...,
		)
		changedHistory, err := l.log.RewriteTenantData(
			operationCtx, tenantID, rewriter.Transform, historyOptions...,
		)
		if err != nil {
			return l.failRotation(operationCtx, domain, "hot_history_rewrite_failed", "tenant hot-history rewrite failed", err)
		}

		retired := domain.Generation
		now := time.Now().UTC()
		domain.Generation = domain.NextGeneration
		domain.WrapperKind, domain.WrapperID = domain.NextWrapperKind, domain.NextWrapperID
		domain.WrappedDomainKEK = domain.NextWrappedDomainKEK
		domain.NextGeneration, domain.NextWrapperKind, domain.NextWrapperID = 0, "", ""
		domain.NextWrappedDomainKEK = nil
		domain.State = store.TenantKeyDomainStateUnsealed
		domain.OperationStatus = store.TenantKeyOperationCompleted
		domain.ProgressCompleted = domain.ProgressTotal
		domain.ProgressCursor = tenantKeyDomainHistoryStage
		domain.MigrationStage = tenantKeyDomainHistoryStage
		domain.Retryable = false
		domain.LastErrorCode, domain.LastError = "", ""
		domain.RotatedAt = &now
		domain.LastTransitionEvidenceRefs = []string{
			fmt.Sprintf("tenant-history://generation-rewrite?changed_events=%d", changedHistory),
			fmt.Sprintf("tenant-domain://generation-%d-retired-from-hot-state-and-history", retired),
			"tenant-history://archives-exports-and-backups-taken-before-rotation-keep-the-previous-generation",
		}
		if err := l.appendSnapshot(operationCtx, tenantID, projections.EventTenantKeyDomainRotationCompleted, domain); err != nil {
			return err
		}
		out, err = l.store.GetTenantKeyDomain(operationCtx, tenantID)
		return err
	})
	return out, err
}

// rotationKeys holds one rotation pass's two transient domain KEKs and the
// bindings they were authenticated under.
type rotationKeys struct {
	current, next                TransientDomainKEK
	sourceBinding, targetBinding []byte
}

func (k *rotationKeys) destroy() {
	if k.current != nil {
		k.current.Destroy()
	}
	if k.next != nil {
		k.next.Destroy()
	}
}

func (l *Lifecycle) validateRotationPreconditions(tenantID string, ref WrapperRef) error {
	if l == nil || l.store == nil || l.log == nil || l.projector == nil || l.manager == nil {
		return ErrLifecycleNotConfigured
	}
	if strings.TrimSpace(tenantID) == "" {
		return errors.New("tenantseal: rotation requires tenant_id (AN-1)")
	}
	if ref != (WrapperRef{}) &&
		((ref.Kind != WrapperKindLocalFile && ref.Kind != WrapperKindPKCS11) ||
			strings.TrimSpace(ref.ID) == "" || strings.TrimSpace(ref.ID) != ref.ID) {
		return ErrWrapperNotConfigured
	}
	if err := l.log.HistoryRewriteReady(); err != nil {
		return err
	}
	return events.ValidateTenantDataRewriteOptions(l.rewriteOptions...)
}

// beginOrResumeRotation authenticates the current generation's KEK, then either
// resumes the running or failed rotation (whose target an explicit ref must
// match) or creates the next generation's KEK and records the rotation start.
// Creating the KEK comes before any event, so a target wrapper that cannot
// create one leaves the domain exactly as it was.
func (l *Lifecycle) beginOrResumeRotation(
	ctx context.Context,
	tenantID string,
	ref WrapperRef,
) (store.TenantKeyDomain, *rotationKeys, error) {
	var domain store.TenantKeyDomain
	keys := &rotationKeys{}
	err := l.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := l.store.LockTenantKeyDomainExclusiveTx(ctx, tx, tenantID); err != nil {
			return err
		}
		existing, err := l.store.GetTenantKeyDomainTx(ctx, tx, tenantID)
		if errors.Is(err, store.ErrTenantKeyDomainNotFound) {
			return ErrLifecycleConflict
		}
		if err != nil {
			return err
		}
		mode, _ := resolveDomainAccessMode(tenantID, existing)
		resuming := mode == domainAccessDualRotation
		switch {
		case resuming:
			if ref != (WrapperRef{}) && ref != (WrapperRef{Kind: existing.NextWrapperKind, ID: existing.NextWrapperID}) {
				return ErrLifecycleConflict
			}
		case mode != domainAccessTenantOnly || existing.State == store.TenantKeyDomainStateSealQueued:
			return ErrLifecycleConflict
		}

		keys.sourceBinding, err = DomainBinding(existing.TenantID, existing.DomainID, existing.Generation)
		if err != nil {
			return statusError(StatusCorrupt, err)
		}
		keys.targetBinding, err = DomainBinding(existing.TenantID, existing.DomainID, existing.Generation+1)
		if err != nil {
			return statusError(StatusCorrupt, err)
		}
		keys.current, err = l.manager.OpenDomainKEK(
			ctx, WrapperRef{Kind: existing.WrapperKind, ID: existing.WrapperID},
			existing.WrappedDomainKEK, keys.sourceBinding,
		)
		if err != nil {
			return classifyDomainOpenError(err)
		}
		domain = existing
		if resuming {
			keys.next, err = l.manager.OpenDomainKEK(
				ctx, WrapperRef{Kind: existing.NextWrapperKind, ID: existing.NextWrapperID},
				existing.NextWrappedDomainKEK, keys.targetBinding,
			)
			if err != nil {
				return classifyDomainOpenError(err)
			}
			domain.OperationStatus = store.TenantKeyOperationRunning
			domain.Retryable = true
			domain.LastErrorCode, domain.LastError = "", ""
			return l.appendSnapshotTx(ctx, tx, tenantID, projections.EventTenantKeyDomainRotationProgressed, domain)
		}

		target := ref
		if target == (WrapperRef{}) {
			target = WrapperRef{Kind: existing.WrapperKind, ID: existing.WrapperID}
		}
		created, wrapped, err := l.manager.CreateDomainKEK(ctx, target, keys.targetBinding)
		if err != nil {
			return classifyDomainOpenError(err)
		}
		keys.next = created
		operationID := uuid.NewString()
		domain.NextGeneration = existing.Generation + 1
		domain.NextWrapperKind, domain.NextWrapperID = target.Kind, target.ID
		domain.NextWrappedDomainKEK = wrapped
		domain.State = store.TenantKeyDomainStateRotating
		domain.OperationID = &operationID
		domain.OperationKind = store.TenantKeyOperationRotate
		domain.OperationStatus = store.TenantKeyOperationRunning
		domain.MigrationStage = "created"
		domain.ProgressCompleted = 0
		domain.ProgressTotal = int64(len(store.TenantKeyDomainCiphertextMigrationStages()) + 1)
		domain.ProgressCursor = ""
		domain.Retryable = true
		domain.LastErrorCode, domain.LastError = "", ""
		domain.LastTransitionEvidenceRefs = []string{
			"tenant-domain://current-generation-kek-authenticated",
			"tenant-domain://next-generation-kek-created",
		}
		return l.appendSnapshotTx(ctx, tx, tenantID, projections.EventTenantKeyDomainRotationStarted, domain)
	})
	if err != nil {
		keys.destroy()
		return store.TenantKeyDomain{}, nil, err
	}
	return domain, keys, nil
}

// failRotation records a visible, retryable failure. The domain stays rotating,
// so both generations remain readable and a retry resumes; only a corrupt
// record stops tenant crypto.
func (l *Lifecycle) failRotation(
	ctx context.Context,
	domain store.TenantKeyDomain,
	code, publicMessage string,
	cause error,
) error {
	domain.State = store.TenantKeyDomainStateRotating
	domain.Retryable = true
	if status, ok := StatusOf(cause); ok && status == StatusCorrupt {
		domain.State = store.TenantKeyDomainStateCorrupt
		domain.Retryable = false
	}
	domain.OperationStatus = store.TenantKeyOperationFailed
	domain.LastErrorCode = code
	domain.LastError = publicMessage
	if err := l.appendSnapshot(ctx, domain.TenantID, projections.EventTenantKeyDomainRotationFailed, domain); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}
