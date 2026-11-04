// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Factory provisioning (P12). Each birth certificate a station's journal
// reports is recorded once, counted against its batch's quota under the
// batch's row lock, so two reconciles of one journal cannot both fit inside
// the quota; a birth certificate past the quota is recorded as over-production.

// ErrFactoryBirthRecorded reports a birth certificate the batch already holds.
var ErrFactoryBirthRecorded = errors.New("orchestrator: the batch already recorded this birth certificate")

// CreateFactoryBatch records a new batch.
func (o *Orchestrator) CreateFactoryBatch(ctx context.Context, tenantID string, created projections.FactoryBatchCreated) error {
	if err := projections.ValidateFactoryBatchCreated(created); err != nil {
		return err
	}
	data, err := json.Marshal(created)
	if err != nil {
		return err
	}
	ev, err := o.emitPrepared(ctx, events.Event{ID: created.ID, Type: projections.EventFactoryBatchCreated, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	if ev.ID != created.ID || ev.Type != projections.EventFactoryBatchCreated {
		return fmt.Errorf("%w: factory batch changed", store.ErrIdempotencyConflict)
	}
	return nil
}

// FactoryBirthEventID is the one event a birth certificate is recorded under.
func FactoryBirthEventID(tenantID, batchID, serial string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("factory-birth\x00"+tenantID+"\x00"+batchID+"\x00"+serial)).String()
}

// RecordFactoryBirth records one reconciled birth certificate, deciding under
// the batch's lock whether it is past the quota. It returns whether it was
// over the quota, or ErrFactoryBirthRecorded for one already recorded.
func (o *Orchestrator) RecordFactoryBirth(ctx context.Context, tenantID string, birth projections.FactoryBirthRecorded) (bool, error) {
	if o == nil || o.log == nil || o.store == nil {
		return false, errors.New("factory provisioning is not configured")
	}
	over := false
	err := o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		batch, err := o.store.LockFactoryBatchTx(ctx, tx, tenantID, birth.BatchID)
		if err != nil {
			return err
		}
		exists, err := o.store.FactoryBirthExistsTx(ctx, tx, tenantID, batch.ID, birth.Serial)
		if err != nil {
			return err
		}
		if exists {
			return ErrFactoryBirthRecorded
		}
		birth.OverQuota = batch.Recorded >= batch.Quota
		over = birth.OverQuota
		data, err := json.Marshal(birth)
		if err != nil {
			return err
		}
		id := FactoryBirthEventID(tenantID, batch.ID, birth.Serial)
		canonical, err := o.log.Append(ctx, events.Event{ID: id, TenantID: tenantID, Type: projections.EventFactoryBirthRecorded, Data: data})
		if err != nil {
			return err
		}
		if canonical.ID != id || canonical.Type != projections.EventFactoryBirthRecorded {
			return fmt.Errorf("%w: factory birth certificate changed", store.ErrIdempotencyConflict)
		}
		return o.proj.ApplyTx(ctx, tx, canonical)
	})
	return over, err
}

// RecordFactoryDeviceEnrolled records a device's first boot or a renewal with
// the operational certificate it was given. Recording it twice records it once.
func (o *Orchestrator) RecordFactoryDeviceEnrolled(ctx context.Context, tenantID string, enrolled projections.FactoryDeviceEnrolled) error {
	data, err := json.Marshal(enrolled)
	if err != nil {
		return err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("factory-enrolled\x00"+tenantID+"\x00"+enrolled.BatchID+"\x00"+enrolled.Serial+
		"\x00"+enrolled.OperationalSerial)).String()
	ev, err := o.emitPrepared(ctx, events.Event{ID: id, Type: projections.EventFactoryDeviceEnrolled, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	if ev.ID != id || ev.Type != projections.EventFactoryDeviceEnrolled {
		return fmt.Errorf("%w: factory enrollment changed", store.ErrIdempotencyConflict)
	}
	return nil
}
