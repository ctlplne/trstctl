// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

type applicationSecretRecoveryVerifierContextKey struct{}

type tenantKeyRecoveryHistorySource interface {
	WithHistoryRead(context.Context, func(context.Context) error) error
	LastSequence(context.Context) (uint64, error)
	ReplayThrough(context.Context, uint64, uint64, func(events.Event) error) error
}

func isTenantKeyDomainHistoryEvent(eventType string) bool {
	switch eventType {
	case EventTenantKeyDomainMigrationStarted, EventTenantKeyDomainMigrationProgressed,
		EventTenantKeyDomainMigrationCompleted, EventTenantKeyDomainMigrationFailed,
		EventTenantKeyDomainSealRequested, EventTenantKeyDomainSealFailed,
		EventTenantKeyDomainSealed, EventTenantKeyDomainUnsealRequested,
		EventTenantKeyDomainUnsealed, EventTenantKeyDomainRotationStarted,
		EventTenantKeyDomainRotationProgressed, EventTenantKeyDomainRotationCompleted,
		EventTenantKeyDomainRotationFailed:
		return true
	default:
		return false
	}
}

// StageTenantKeyRecoveryHistory derives operation-bound key state from the
// pinned source stream before a read-model replacement can truncate
// tenant_key_domains. It streams one event at a time to tenant-scoped SQL;
// it never trusts an existing read-model row for this recovery authority.
func StageTenantKeyRecoveryHistory(ctx context.Context, st *store.Store, log *events.Log, operationID string) error {
	if st == nil || log == nil || operationID == "" {
		return errors.New("projections: recovery key-history staging is incomplete")
	}
	return log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := projectionHistoryHead(readCtx, log)
		if err != nil {
			return err
		}
		return stageTenantKeyRecoveryHistoryThrough(readCtx, st, log, operationID, head)
	})
}

func stageTenantKeyRecoveryHistoryThrough(
	ctx context.Context, st *store.Store, log *events.Log, operationID string, head uint64,
) error {
	return replayProjectionThrough(ctx, log, 0, head, func(event events.Event) error {
		return stageTenantKeyRecoveryEvent(ctx, st, operationID, event)
	})
}

// StageTenantKeyRecoveryArtifactHistory stages the same tenant lifecycle and
// key-domain snapshots from an already verified, read-only artifact source.
// The caller must keep the source's HMAC verification scope alive through this
// callback, before the target event log is populated.
func StageTenantKeyRecoveryArtifactHistory(ctx context.Context, st *store.Store,
	source tenantKeyRecoveryHistorySource, operationID string,
) error {
	if st == nil || source == nil || operationID == "" {
		return errors.New("projections: artifact recovery key-history staging is incomplete")
	}
	return source.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := source.LastSequence(readCtx)
		if err != nil {
			return err
		}
		return source.ReplayThrough(readCtx, 0, head, func(event events.Event) error {
			return stageTenantKeyRecoveryEvent(readCtx, st, operationID, event)
		})
	})
}

func stageTenantKeyRecoveryEvent(ctx context.Context, st *store.Store,
	operationID string, event events.Event,
) error {
	switch event.Type {
	case EventTenantRegistered, EventTenantOffboarded:
		if err := ValidateSchemaVersion(event); err != nil {
			return err
		}
		if event.ID == "" || event.TenantID == "" || event.Sequence == 0 {
			return fmt.Errorf("projections: recovery tenant lifecycle event is incomplete at sequence %d", event.Sequence)
		}
		return st.StageTenantKeyRecoveryLifecycle(ctx, operationID, event.TenantID,
			event.ID, event.Sequence, event.Type == EventTenantRegistered)
	default:
		if !isTenantKeyDomainHistoryEvent(event.Type) {
			return nil
		}
	}
	if err := ValidateSchemaVersion(event); err != nil {
		return err
	}
	if event.ID == "" || event.TenantID == "" || event.Time.IsZero() || event.Sequence == 0 {
		return fmt.Errorf("projections: recovery key-domain event is incomplete at sequence %d", event.Sequence)
	}
	var snapshot TenantKeyDomainSnapshot
	if err := decode(event, &snapshot); err != nil {
		return err
	}
	if err := validateTenantKeyDomainSnapshot(event.Type, snapshot); err != nil {
		return err
	}
	return st.StageTenantKeyRecoverySnapshot(ctx, operationID, tenantKeyDomainFromSnapshot(event, snapshot))
}

func tenantKeyDomainFromSnapshot(event events.Event, snapshot TenantKeyDomainSnapshot) store.TenantKeyDomain {
	createdAt := snapshot.CreatedAt
	if createdAt.IsZero() {
		createdAt = event.Time
	}
	updatedAt := snapshot.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = event.Time
	}
	if event.Type == EventTenantKeyDomainMigrationStarted && snapshot.MigrationStartedAt == nil {
		at := event.Time
		snapshot.MigrationStartedAt = &at
	}
	if event.Type == EventTenantKeyDomainMigrationCompleted && snapshot.MigrationCompletedAt == nil {
		at := event.Time
		snapshot.MigrationCompletedAt = &at
	}
	if event.Type == EventTenantKeyDomainSealed && snapshot.SealedAt == nil {
		at := event.Time
		snapshot.SealedAt = &at
	}
	if event.Type == EventTenantKeyDomainUnsealed && snapshot.UnsealedAt == nil {
		at := event.Time
		snapshot.UnsealedAt = &at
	}
	if event.Type == EventTenantKeyDomainRotationCompleted && snapshot.RotatedAt == nil {
		at := event.Time
		snapshot.RotatedAt = &at
	}
	actor := ""
	if event.Actor != nil {
		actor = event.Actor.Subject
	}
	return store.TenantKeyDomain{
		TenantID: event.TenantID, DomainID: snapshot.DomainID, Generation: snapshot.Generation,
		ProtectionMode: snapshot.ProtectionMode, State: snapshot.State,
		WrapperKind: snapshot.WrapperKind, WrapperID: snapshot.WrapperID,
		WrappedDomainKEK: snapshot.WrappedDomainKEK, NextGeneration: snapshot.NextGeneration,
		NextWrapperKind: snapshot.NextWrapperKind, NextWrapperID: snapshot.NextWrapperID,
		NextWrappedDomainKEK: snapshot.NextWrappedDomainKEK, RotatedAt: snapshot.RotatedAt,
		OperationID: snapshot.OperationID, OperationKind: snapshot.OperationKind,
		OperationStatus: snapshot.OperationStatus, MigrationStage: snapshot.MigrationStage,
		ProgressCompleted: snapshot.ProgressCompleted, ProgressTotal: snapshot.ProgressTotal,
		ProgressCursor: snapshot.ProgressCursor, Retryable: snapshot.Retryable,
		LastErrorCode: snapshot.LastErrorCode, LastError: snapshot.LastError,
		LegacyHistoryExposure: snapshot.LegacyHistoryExposure,
		MigrationStartedAt:    snapshot.MigrationStartedAt,
		MigrationCompletedAt:  snapshot.MigrationCompletedAt,
		SealedAt:              snapshot.SealedAt, UnsealedAt: snapshot.UnsealedAt,
		LastTransitionEventID: event.ID, LastTransitionType: event.Type,
		LastTransitionActor: actor, LastTransitionAt: event.Time,
		LastTransitionEvidenceRefs: snapshot.TransitionEvidenceRefs,
		LastTransitionSequence:     event.Sequence, CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
}
