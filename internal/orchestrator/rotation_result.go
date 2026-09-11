// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// RecordRotationResultWithEventID persists one terminal host observation. A
// repeated signed report reuses the event; a changed result fails closed.
func (o *Orchestrator) RecordRotationResultWithEventID(ctx context.Context, tenantID, eventID string, r store.RotationRun, retained *events.Event) error {
	if eventID == "" || r.CompletedAt == nil || (r.Status != "succeeded" && r.Status != "failed") {
		return errors.New("orchestrator: rotation result requires an event ID and terminal observation")
	}
	data, err := json.Marshal(projections.LifecycleRotationRecorded{
		ID: r.ID, IdentityID: r.IdentityID, OutboxID: r.OutboxID, Status: r.Status,
		Trigger: r.Trigger, Reason: r.Reason, PredecessorFingerprint: r.PredecessorFingerprint,
		SuccessorFingerprint: r.SuccessorFingerprint, RollbackRef: r.RollbackRef,
		Error: r.Error, IdempotencyKey: r.IdempotencyKey, CompletedAt: r.CompletedAt,
	})
	if err != nil {
		return err
	}
	// The caller has checked a bounded, generation-pinned source index. Reuse
	// the retained envelope after an interrupted projection, even after dedupe expiry.
	if retained != nil {
		if retained.ID != eventID || retained.TenantID != tenantID || retained.Type != projections.EventLifecycleRotationRecorded || !bytes.Equal(retained.Data, data) {
			return fmt.Errorf("%w: retained host rotation result differs", store.ErrIdempotencyConflict)
		}
		return o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return o.proj.ApplyTx(ctx, tx, *retained)
		})
	}
	_, err = o.emitPreparedExact(ctx, events.Event{
		ID: eventID, TenantID: tenantID, Type: projections.EventLifecycleRotationRecorded, Data: data, Time: *r.CompletedAt,
	})
	return err
}
