// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

// ProjectServiceReconciliationFence restores only an already-claimed command.
// It does not open directory credentials or perform a native reset; its outbox
// work remains bounded and subject to the configured worker's exact authority.
func ProjectServiceReconciliationFence(ctx context.Context, st *store.Store, log *events.Log, fence store.ApprovedTargetFence) error {
	if st == nil || log == nil {
		return errors.New("api: reconciliation recovery needs store and event log")
	}
	return (&API{store: st, log: log}).projectServiceReconcileFence(ctx, fence.TenantID, fence)
}
func (a *API) projectServiceReconcileFence(ctx context.Context, tenantID string, fence store.ApprovedTargetFence) error {
	if fence.TenantID != tenantID || fence.TargetKind != store.ApprovedTargetServiceReconciliation {
		return store.ErrIdempotencyConflict
	}
	return a.store.WithPrivacyRecoveryBarrier(ctx, tenantID, "approved directory reconciliation recovery", func(ctx context.Context) error {
		latest, err := a.store.GetApprovedTargetFence(ctx, tenantID, store.ApprovedTargetServiceReconciliation, fence.CommandKey)
		if store.IsNotFound(err) {
			return a.completedServiceReconcileFence(ctx, tenantID, fence)
		}
		if err != nil {
			return err
		}
		if latest.EventID != fence.EventID || latest.RequestBinding != fence.RequestBinding {
			return store.ErrIdempotencyConflict
		}
		retained, found, err := a.log.EventByID(ctx, latest.EventID)
		if err != nil {
			return err
		}
		err = a.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			locked, _, _, err := a.store.LockApprovedTargetFenceTx(ctx, tx, tenantID, store.ApprovedTargetServiceReconciliation, latest.CommandKey)
			if err != nil {
				return err
			}
			var payload projections.ServiceDependentRotationQueued
			if json.Unmarshal(locked.Payload, &payload) != nil {
				return store.ErrIdempotencyConflict
			}
			candidate := events.Event{ID: locked.EventID, TenantID: tenantID, Type: locked.EventType, SchemaVersion: locked.SchemaVersion, Time: locked.EventTime, Actor: locked.Actor, Data: locked.Payload}
			semantic, err := projections.ServiceReconcileSemanticDigest(candidate, payload)
			if err != nil {
				return err
			}
			digest, err := payload.Intent.Digest()
			if err != nil || digest != locked.RequestBinding || locked.SemanticDigest != semantic || locked.CommandKey != servicedependents.ReconcileCommandKey(tenantID, payload.Intent.Plan.SecretName) {
				return store.ErrIdempotencyConflict
			}
			event := retained
			if !found {
				event, err = a.log.Append(ctx, candidate)
				if err != nil {
					return err
				}
			}
			var canonical projections.ServiceDependentRotationQueued
			if event.ID != candidate.ID || event.Type != candidate.Type || event.TenantID != tenantID || event.SchemaVersion != candidate.SchemaVersion || !event.Time.Equal(candidate.Time) || json.Unmarshal(event.Data, &canonical) != nil {
				return store.ErrIdempotencyConflict
			}
			actual, err := projections.ServiceReconcileSemanticDigest(event, canonical)
			if err != nil || actual != semantic {
				return store.ErrIdempotencyConflict
			}
			if err := projections.New(a.store).ApplyTx(ctx, tx, event); err != nil {
				return err
			}
			parent, err := a.store.GetServiceDependentRotationTx(ctx, tx, tenantID, event.ID)
			if err != nil {
				return err
			}
			if parent.IntentDigest != digest || parent.CommandID != event.ID {
				return store.ErrIdempotencyConflict
			}
			return nil
		})
		if store.IsNotFound(err) {
			return a.completedServiceReconcileFence(ctx, tenantID, fence)
		}
		return err
	})
}

func serviceReconciliationFenceEvent(fence store.ApprovedTargetFence) events.Event {
	return events.Event{ID: fence.EventID, TenantID: fence.TenantID, Type: fence.EventType, SchemaVersion: fence.SchemaVersion, Time: fence.EventTime, Actor: fence.Actor, Data: fence.Payload}
}

// A concurrent publisher may retire the row before a startup retry gets its
// lock. Absence alone is never success: verify the exact canonical command and
// the already-created parent/child, without appending or consuming anything.
func (a *API) completedServiceReconcileFence(ctx context.Context, tenantID string, fence store.ApprovedTargetFence) error {
	event, found, err := a.log.EventByID(ctx, fence.EventID)
	if err != nil {
		return err
	}
	var source projections.ServiceDependentRotationQueued
	if !found || event.TenantID != tenantID || event.Type != fence.EventType || event.SchemaVersion != fence.SchemaVersion || !event.Time.Equal(fence.EventTime) || json.Unmarshal(event.Data, &source) != nil {
		return store.ErrIdempotencyConflict
	}
	semantic, err := projections.ServiceReconcileSemanticDigest(event, source)
	if err != nil || semantic != fence.SemanticDigest || fence.CommandKey != servicedependents.ReconcileCommandKey(tenantID, source.Intent.Plan.SecretName) {
		return store.ErrIdempotencyConflict
	}
	cmd, err := a.store.GetSecretStaticRotationCommand(ctx, tenantID, event.ID)
	if err != nil {
		return err
	}
	parent, err := a.dependentRotationParent(ctx, cmd)
	if err != nil {
		return err
	}
	if parent.ID != event.ID || parent.IntentDigest != fence.RequestBinding || parent.CommandID != event.ID {
		return store.ErrIdempotencyConflict
	}
	return nil
}
