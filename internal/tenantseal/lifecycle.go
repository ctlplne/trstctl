// SPDX-License-Identifier: MPL-2.0

package tenantseal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var (
	ErrLifecycleNotConfigured = errors.New("tenantseal: lifecycle is not configured")
	ErrMigrationAlreadyDone   = errors.New("tenantseal: tenant key-domain migration is already complete")
	ErrLifecycleConflict      = errors.New("tenantseal: tenant key-domain lifecycle state conflicts with this operation")
)

const tenantKeyDomainHistoryStage = "jetstream_hot_history"

var tenantKeyDomainSealOperationNamespace = uuid.MustParse("ebffb468-4321-4d13-8f5f-3b56515744ec")

// DomainKEKManager combines the exact wrapper operations needed by the served
// lifecycle. LocalWrapperRegistry is the CORE implementation and performs zero
// egress. A future remote implementation must live behind a bounded outbox
// worker rather than implementing this request-path interface.
type DomainKEKManager interface {
	DomainKEKRegistry
	DomainKEKCreator
}

// Lifecycle coordinates one tenant's independently wrapped key domain across
// PostgreSQL hot state and the canonical JetStream event generation.
type Lifecycle struct {
	store          *store.Store
	log            *events.Log
	projector      *projections.Projector
	deployment     seal.KeyWrapper
	manager        DomainKEKManager
	rewriteOptions []events.TenantDataRewriteOption
}

// NewLifecycle builds the CORE local-custody lifecycle. It does not open any
// wrapper or mutate state. Migrate preflights every history proof wall before it
// emits the first lifecycle event.
func NewLifecycle(
	st *store.Store,
	log *events.Log,
	deployment seal.KeyWrapper,
	manager DomainKEKManager,
	rewriteOptions ...events.TenantDataRewriteOption,
) (*Lifecycle, error) {
	if st == nil || log == nil || deployment == nil || manager == nil {
		return nil, ErrLifecycleNotConfigured
	}
	return &Lifecycle{
		store: st, log: log, projector: projections.New(st),
		deployment: deployment, manager: manager,
		rewriteOptions: append([]events.TenantDataRewriteOption(nil), rewriteOptions...),
	}, nil
}

// Status returns the persisted tenant-domain projection. A missing row remains
// an explicit ErrTenantKeyDomainNotFound so the API can report
// legacy_deployment_kek without inventing a migrated record.
func (l *Lifecycle) Status(ctx context.Context, tenantID string) (store.TenantKeyDomain, error) {
	if l == nil || l.store == nil {
		return store.TenantKeyDomain{}, ErrLifecycleNotConfigured
	}
	return l.store.GetTenantKeyDomain(ctx, tenantID)
}

// Migrate creates or resumes one tenant domain, rewraps every known hot-state
// CSL container without payload plaintext, switches the canonical event-log
// generation with signed continuity, and leaves an honest partial state because
// external archives/exports/backups may retain deployment-domain bytes.
func (l *Lifecycle) Migrate(
	ctx context.Context,
	tenantID string,
	ref WrapperRef,
) (store.TenantKeyDomain, error) {
	if err := l.validateMigrationPreconditions(tenantID, ref); err != nil {
		return store.TenantKeyDomain{}, err
	}
	var out store.TenantKeyDomain
	err := l.log.WithHistoryOperation(ctx, func(operationCtx context.Context) error {
		domain, key, err := l.beginOrResumeMigration(operationCtx, tenantID, ref)
		if err != nil {
			return err
		}
		defer key.Destroy()
		binding, err := DomainBinding(domain.TenantID, domain.DomainID, domain.Generation)
		if err != nil {
			return l.failMigration(operationCtx, domain, "domain_binding_invalid", "tenant domain binding is invalid", err)
		}
		rewriter, err := NewHistoryRewrapper(l.deployment, key, binding)
		if err != nil {
			return l.failMigration(operationCtx, domain, "rewrapper_unavailable", "tenant ciphertext rewrapper is unavailable", err)
		}

		stages := store.TenantKeyDomainCiphertextMigrationStages()
		for index, stage := range stages {
			if _, err := l.store.RewriteTenantKeyDomainCiphertextStage(
				operationCtx, tenantID, stage,
				func(before []byte) ([]byte, bool, error) {
					return rewriter.Transform("postgres."+stage, 1, before)
				},
			); err != nil {
				return l.failMigration(operationCtx, domain, "hot_state_rewrap_failed", "tenant hot-state rewrap failed", err)
			}
			domain.ProgressCompleted = int64(index + 1)
			domain.ProgressCursor = stage
			domain.MigrationStage = stage
			domain.State = store.TenantKeyDomainStateMigrating
			domain.OperationStatus = store.TenantKeyOperationRunning
			domain.Retryable = true
			domain.LastErrorCode, domain.LastError = "", ""
			if err := l.appendSnapshot(operationCtx, tenantID, projections.EventTenantKeyDomainMigrationProgressed, domain); err != nil {
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
			return l.failMigration(operationCtx, domain, "hot_history_rewrite_failed", "tenant hot-history rewrite failed", err)
		}
		domain.ProgressCompleted = domain.ProgressTotal
		domain.ProgressCursor = tenantKeyDomainHistoryStage
		domain.MigrationStage = tenantKeyDomainHistoryStage
		domain.State = store.TenantKeyDomainStatePartial
		domain.OperationStatus = store.TenantKeyOperationCompleted
		domain.Retryable = false
		domain.LegacyHistoryExposure = store.TenantKeyLegacyExternalArchivesPossible
		domain.LastErrorCode, domain.LastError = "", ""
		now := time.Now().UTC()
		domain.MigrationCompletedAt = &now
		domain.LastTransitionEvidenceRefs = []string{
			fmt.Sprintf("tenant-history://generation-rewrite?changed_events=%d", changedHistory),
			"tenant-history://external-archives-exports-and-backups-may-retain-source-bytes",
		}
		if err := l.appendSnapshot(operationCtx, tenantID, projections.EventTenantKeyDomainMigrationCompleted, domain); err != nil {
			return err
		}
		out, err = l.store.GetTenantKeyDomain(operationCtx, tenantID)
		return err
	})
	return out, err
}

// SealOperationID is the stable receiver identity for one authenticated seal
// request. A retry on another replica derives the same UUID; a reused raw key
// with another route/caller binding derives a different UUID and fails closed.
func SealOperationID(tenantID, idempotencyKey, requestBinding string) (string, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(idempotencyKey) == "" ||
		strings.TrimSpace(requestBinding) == "" {
		return "", errors.New("tenantseal: seal request requires tenant, idempotency key, and request binding")
	}
	return uuid.NewSHA1(
		tenantKeyDomainSealOperationNamespace,
		[]byte(tenantID+"\x00"+idempotencyKey+"\x00"+requestBinding),
	).String(), nil
}

// RequestSeal appends the immutable seal request and projects its derived
// bounded-worker command atomically. The honest seal_queued state still permits
// tenant crypto: the worker must first prove the accepted idempotency result is
// complete. Exact retries repair a missing derived outbox row.
func (l *Lifecycle) RequestSeal(
	ctx context.Context,
	tenantID, idempotencyKey, requestBinding string,
) (store.TenantKeyDomain, error) {
	if l == nil || l.store == nil || l.log == nil || l.projector == nil {
		return store.TenantKeyDomain{}, ErrLifecycleNotConfigured
	}
	operationID, err := SealOperationID(tenantID, idempotencyKey, requestBinding)
	if err != nil {
		return store.TenantKeyDomain{}, err
	}
	var out store.TenantKeyDomain
	err = l.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := l.store.LockTenantKeyDomainExclusiveTx(ctx, tx, tenantID); err != nil {
			return err
		}
		domain, err := l.store.GetTenantKeyDomainTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		matches := domain.OperationID != nil && *domain.OperationID == operationID &&
			domain.OperationKind == store.TenantKeyOperationSeal
		switch {
		case domain.State == store.TenantKeyDomainStateSealed && matches:
			out = domain
			return nil
		case domain.State == store.TenantKeyDomainStateSealQueued && matches &&
			domain.OperationStatus == store.TenantKeyOperationPending:
			if err := l.store.EnsureTenantKeyDomainSealOutboxTx(
				ctx, tx, tenantID, operationID, idempotencyKey, requestBinding,
			); err != nil {
				return err
			}
			out = domain
			return nil
		case domain.State != store.TenantKeyDomainStatePartial &&
			domain.State != store.TenantKeyDomainStateUnsealed:
			return ErrLifecycleConflict
		}

		domain.OperationID = &operationID
		domain.OperationKind = store.TenantKeyOperationSeal
		domain.OperationStatus = store.TenantKeyOperationPending
		domain.State = store.TenantKeyDomainStateSealQueued
		domain.Retryable = true
		domain.LastErrorCode, domain.LastError = "", ""
		domain.LastTransitionEvidenceRefs = []string{
			"tenant-domain://seal-request-durable",
			"tenant-domain://awaiting-idempotency-result-wall",
		}
		snapshot := snapshotFromDomain(domain)
		snapshot.SealIdempotencyKey = idempotencyKey
		snapshot.SealRequestBinding = requestBinding
		payload, err := json.Marshal(snapshot)
		if err != nil {
			return err
		}
		event, err := l.log.Append(ctx, events.Event{
			Type:     projections.EventTenantKeyDomainSealRequested,
			TenantID: tenantID, SchemaVersion: 1, Data: payload,
		})
		if err != nil {
			return err
		}
		if err := l.projector.ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		out = domain
		return nil
	})
	if err != nil {
		return store.TenantKeyDomain{}, err
	}
	return out, nil
}

// CompleteSeal is the bounded worker's idempotent receiver. Its caller has
// already proven the idempotency result is completed. The exclusive fence waits
// for every shared crypto callback on every replica; new callbacks block until
// commit and then observe sealed. Resolver keeps no long-lived key cache, so all
// transient domain keys are destroyed before this transaction can proceed.
func (l *Lifecycle) CompleteSeal(
	ctx context.Context,
	tenantID, operationID string,
) (store.TenantKeyDomain, error) {
	if l == nil || l.store == nil || l.log == nil || l.projector == nil ||
		strings.TrimSpace(tenantID) == "" || strings.TrimSpace(operationID) == "" {
		return store.TenantKeyDomain{}, ErrLifecycleNotConfigured
	}
	var out store.TenantKeyDomain
	err := l.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := l.store.LockTenantKeyDomainExclusiveTx(ctx, tx, tenantID); err != nil {
			return err
		}
		domain, err := l.store.GetTenantKeyDomainTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		matches := domain.OperationID != nil && *domain.OperationID == operationID &&
			domain.OperationKind == store.TenantKeyOperationSeal
		if domain.State == store.TenantKeyDomainStateSealed && matches &&
			domain.OperationStatus == store.TenantKeyOperationCompleted {
			out = domain
			return nil
		}
		if !matches || domain.State != store.TenantKeyDomainStateSealQueued ||
			domain.OperationStatus != store.TenantKeyOperationPending {
			return ErrLifecycleConflict
		}

		now := time.Now().UTC()
		domain.State = store.TenantKeyDomainStateSealed
		domain.OperationStatus = store.TenantKeyOperationCompleted
		domain.Retryable = false
		domain.SealedAt = &now
		domain.LastErrorCode, domain.LastError = "", ""
		domain.LastTransitionEvidenceRefs = []string{
			"tenant-domain://idempotency-result-completed",
			"tenant-domain://exclusive-fence-drained",
		}
		if err := l.appendSnapshotTx(
			ctx, tx, tenantID, projections.EventTenantKeyDomainSealed, domain,
		); err != nil {
			return err
		}
		out = domain
		return nil
	})
	if err != nil {
		return store.TenantKeyDomain{}, err
	}
	return out, nil
}

// Unseal proves the configured wrapper can authenticate and open the exact
// persisted tenant-domain KEK before making the domain available again.
func (l *Lifecycle) Unseal(ctx context.Context, tenantID string) (store.TenantKeyDomain, error) {
	return l.transition(ctx, tenantID, store.TenantKeyOperationUnseal)
}

func (l *Lifecycle) validateMigrationPreconditions(tenantID string, ref WrapperRef) error {
	if l == nil || l.store == nil || l.log == nil || l.projector == nil || l.deployment == nil || l.manager == nil {
		return ErrLifecycleNotConfigured
	}
	if strings.TrimSpace(tenantID) == "" {
		return errors.New("tenantseal: migration requires tenant_id (AN-1)")
	}
	if ref.Kind != WrapperKindLocalFile || strings.TrimSpace(ref.ID) == "" || strings.TrimSpace(ref.ID) != ref.ID {
		return ErrWrapperNotConfigured
	}
	if err := l.log.HistoryRewriteReady(); err != nil {
		return err
	}
	return events.ValidateTenantDataRewriteOptions(l.rewriteOptions...)
}

func (l *Lifecycle) beginOrResumeMigration(
	ctx context.Context,
	tenantID string,
	ref WrapperRef,
) (store.TenantKeyDomain, TransientDomainKEK, error) {
	var domain store.TenantKeyDomain
	var key TransientDomainKEK
	err := l.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := l.store.LockTenantKeyDomainExclusiveTx(ctx, tx, tenantID); err != nil {
			return err
		}
		current, err := l.store.GetTenantKeyDomainTx(ctx, tx, tenantID)
		switch {
		case errors.Is(err, store.ErrTenantKeyDomainNotFound):
			domainID := uuid.NewString()
			operationID := uuid.NewString()
			binding, err := DomainBinding(tenantID, domainID, 1)
			if err != nil {
				return err
			}
			created, wrapped, err := l.manager.CreateDomainKEK(ctx, ref, binding)
			if err != nil {
				return classifyDomainOpenError(err)
			}
			key = created
			domain = store.TenantKeyDomain{
				TenantID: tenantID, DomainID: domainID, Generation: 1,
				ProtectionMode: store.TenantKeyProtectionTenantDomain,
				State:          store.TenantKeyDomainStateMigrating,
				WrapperKind:    ref.Kind, WrapperID: ref.ID, WrappedDomainKEK: wrapped,
				OperationID: &operationID, OperationKind: store.TenantKeyOperationMigrate,
				OperationStatus: store.TenantKeyOperationRunning,
				MigrationStage:  "created", ProgressCompleted: 0,
				ProgressTotal:         int64(len(store.TenantKeyDomainCiphertextMigrationStages()) + 1),
				Retryable:             true,
				LegacyHistoryExposure: store.TenantKeyLegacyHotHistoryPending,
				CreatedAt:             time.Now().UTC(),
			}
			domain.MigrationStartedAt = &domain.CreatedAt
			return l.appendSnapshotTx(ctx, tx, tenantID, projections.EventTenantKeyDomainMigrationStarted, domain)
		case err != nil:
			return err
		case current.WrapperKind != ref.Kind || current.WrapperID != ref.ID:
			return ErrLifecycleConflict
		case current.OperationKind != store.TenantKeyOperationMigrate:
			return ErrLifecycleConflict
		case current.OperationStatus == store.TenantKeyOperationCompleted:
			return ErrMigrationAlreadyDone
		case current.OperationStatus != store.TenantKeyOperationRunning && current.OperationStatus != store.TenantKeyOperationFailed:
			return ErrLifecycleConflict
		default:
			binding, err := DomainBinding(current.TenantID, current.DomainID, current.Generation)
			if err != nil {
				return err
			}
			opened, err := l.manager.OpenDomainKEK(
				ctx, WrapperRef{Kind: current.WrapperKind, ID: current.WrapperID},
				current.WrappedDomainKEK, binding,
			)
			if err != nil {
				return classifyDomainOpenError(err)
			}
			key, domain = opened, current
			domain.State = store.TenantKeyDomainStateMigrating
			domain.OperationStatus = store.TenantKeyOperationRunning
			domain.Retryable = true
			domain.LastErrorCode, domain.LastError = "", ""
			return l.appendSnapshotTx(ctx, tx, tenantID, projections.EventTenantKeyDomainMigrationProgressed, domain)
		}
	})
	if err != nil && key != nil {
		key.Destroy()
		key = nil
	}
	return domain, key, err
}

func (l *Lifecycle) failMigration(
	ctx context.Context,
	domain store.TenantKeyDomain,
	code, publicMessage string,
	cause error,
) error {
	domain.State = store.TenantKeyDomainStatePartial
	if status, ok := StatusOf(cause); ok {
		switch status {
		case StatusWrapperUnavailable:
			domain.State = store.TenantKeyDomainStateWrapperUnavailable
		case StatusUnwrapFailed:
			domain.State = store.TenantKeyDomainStateWrongWrapper
		case StatusCorrupt:
			domain.State = store.TenantKeyDomainStateCorrupt
		}
	}
	domain.OperationStatus = store.TenantKeyOperationFailed
	domain.Retryable = domain.State != store.TenantKeyDomainStateCorrupt
	domain.LastErrorCode = code
	domain.LastError = publicMessage
	if err := l.appendSnapshot(ctx, domain.TenantID, projections.EventTenantKeyDomainMigrationFailed, domain); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func (l *Lifecycle) transition(
	ctx context.Context,
	tenantID, operation string,
) (store.TenantKeyDomain, error) {
	if l == nil || l.store == nil || l.manager == nil {
		return store.TenantKeyDomain{}, ErrLifecycleNotConfigured
	}
	if strings.TrimSpace(tenantID) == "" {
		return store.TenantKeyDomain{}, errors.New("tenantseal: lifecycle requires tenant_id (AN-1)")
	}
	err := l.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := l.store.LockTenantKeyDomainExclusiveTx(ctx, tx, tenantID); err != nil {
			return err
		}
		domain, err := l.store.GetTenantKeyDomainTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		switch operation {
		case store.TenantKeyOperationUnseal:
			if domain.State == store.TenantKeyDomainStateUnsealed {
				return nil
			}
			resuming := domain.State == store.TenantKeyDomainStateUnsealing &&
				domain.OperationKind == operation &&
				domain.OperationStatus == store.TenantKeyOperationRunning
			if !resuming && domain.State != store.TenantKeyDomainStateSealed {
				return ErrLifecycleConflict
			}
			binding, err := DomainBinding(domain.TenantID, domain.DomainID, domain.Generation)
			if err != nil {
				return err
			}
			key, err := l.manager.OpenDomainKEK(
				ctx, WrapperRef{Kind: domain.WrapperKind, ID: domain.WrapperID},
				domain.WrappedDomainKEK, binding,
			)
			if err != nil {
				return classifyDomainOpenError(err)
			}
			key.Destroy()
			if !resuming {
				operationID := uuid.NewString()
				domain.OperationID = &operationID
				domain.OperationKind = operation
				domain.OperationStatus = store.TenantKeyOperationRunning
				domain.State = store.TenantKeyDomainStateUnsealing
				domain.Retryable = true
				if err := l.appendSnapshotTx(ctx, tx, tenantID, projections.EventTenantKeyDomainUnsealRequested, domain); err != nil {
					return err
				}
			}
			now := time.Now().UTC()
			domain.State = store.TenantKeyDomainStateUnsealed
			domain.OperationStatus = store.TenantKeyOperationCompleted
			domain.Retryable = false
			domain.UnsealedAt = &now
			domain.LastTransitionEvidenceRefs = []string{"tenant-domain://wrapper-authenticated"}
			if err := l.appendSnapshotTx(ctx, tx, tenantID, projections.EventTenantKeyDomainUnsealed, domain); err != nil {
				return err
			}
		default:
			return ErrLifecycleConflict
		}
		return nil
	})
	if err != nil {
		return store.TenantKeyDomain{}, err
	}
	return l.store.GetTenantKeyDomain(ctx, tenantID)
}

func (l *Lifecycle) appendSnapshot(
	ctx context.Context,
	tenantID, eventType string,
	domain store.TenantKeyDomain,
) error {
	return l.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := l.store.LockTenantKeyDomainExclusiveTx(ctx, tx, tenantID); err != nil {
			return err
		}
		return l.appendSnapshotTx(ctx, tx, tenantID, eventType, domain)
	})
}

func (l *Lifecycle) appendSnapshotTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, eventType string,
	domain store.TenantKeyDomain,
) error {
	payload, err := json.Marshal(snapshotFromDomain(domain))
	if err != nil {
		return err
	}
	event, err := l.log.Append(ctx, events.Event{
		Type: eventType, TenantID: tenantID, SchemaVersion: 1, Data: payload,
	})
	if err != nil {
		return err
	}
	return l.projector.ApplyTx(ctx, tx, event)
}

func snapshotFromDomain(domain store.TenantKeyDomain) projections.TenantKeyDomainSnapshot {
	return projections.TenantKeyDomainSnapshot{
		DomainID: domain.DomainID, Generation: domain.Generation,
		ProtectionMode: domain.ProtectionMode, State: domain.State,
		WrapperKind: domain.WrapperKind, WrapperID: domain.WrapperID,
		WrappedDomainKEK: append([]byte(nil), domain.WrappedDomainKEK...),
		OperationID:      domain.OperationID, OperationKind: domain.OperationKind,
		OperationStatus: domain.OperationStatus, MigrationStage: domain.MigrationStage,
		ProgressCompleted: domain.ProgressCompleted, ProgressTotal: domain.ProgressTotal,
		ProgressCursor: domain.ProgressCursor, Retryable: domain.Retryable,
		LastErrorCode: domain.LastErrorCode, LastError: domain.LastError,
		LegacyHistoryExposure: domain.LegacyHistoryExposure,
		MigrationStartedAt:    domain.MigrationStartedAt,
		MigrationCompletedAt:  domain.MigrationCompletedAt,
		SealedAt:              domain.SealedAt, UnsealedAt: domain.UnsealedAt,
		TransitionEvidenceRefs: append([]string(nil), domain.LastTransitionEvidenceRefs...),
		CreatedAt:              domain.CreatedAt, UpdatedAt: time.Now().UTC(),
	}
}
