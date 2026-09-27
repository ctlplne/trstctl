// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// RecordCertificateEvent preserves an issuer's existing stable event identity
// while using the same append-order fence, immutable binding and recovery path
// as ordinary certificate recording. Callers must supply a complete public fact.
func (o *Orchestrator) RecordCertificateEvent(ctx context.Context, event events.Event) error {
	if event.ID == "" || event.Type != projections.EventCertificateRecorded {
		return errors.New("orchestrator: a stable certificate recording event is required")
	}
	_, err := o.emitCertificateRecording(ctx, event)
	return err
}

func (o *Orchestrator) emitCertificateRecording(ctx context.Context, next events.Event) (events.Event, error) {
	ctx, releaseTenant, admissionErr := o.beginTenantCommand(ctx, next.TenantID)
	if admissionErr != nil {
		return events.Event{}, admissionErr
	}
	defer releaseTenant()

	material, recording, err := projections.CertificateRecordingMaterial(next)
	if err != nil {
		return events.Event{}, err
	}
	if !recording {
		return events.Event{}, errors.New("orchestrator: expected certificate recording")
	}
	var result events.Event
	err = o.store.WithPrivacyRecoveryBarrier(ctx, next.TenantID, "certificate recording recovery", func(readCtx context.Context) error {
		return o.store.WithTenant(readCtx, next.TenantID, func(tx pgx.Tx) error {
			if err := o.store.LockCertificateRecordingTx(readCtx, tx, next.TenantID, material.Fingerprint); err != nil {
				return err
			}
			retained, found, err := o.catchUpCertificateRecordingAndLookupTx(readCtx, tx, next.TenantID, material.Fingerprint, next.ID)
			if err != nil {
				return err
			}
			if err := o.store.ValidateCertificateIssuanceBindingTx(readCtx, tx, next.TenantID, material); err != nil {
				return err
			}
			if found {
				version := next.SchemaVersion
				if version == 0 {
					version = events.DefaultSchemaVersion
				}
				if retained.Type != next.Type || !sameCertificateRecordingTenant(retained.TenantID, next.TenantID) ||
					retained.SchemaVersion != version || !bytes.Equal(retained.Data, next.Data) {
					return fmt.Errorf("%w: retained certificate command differs", store.ErrIdempotencyConflict)
				}
				result = retained
				return o.proj.ApplyTx(readCtx, tx, retained)
			}
			if err := o.guardCertificateRecordingAppendTx(readCtx, tx, next.TenantID, material); err != nil {
				return err
			}
			result, err = o.log.Append(readCtx, next)
			if err != nil {
				return err
			}
			return o.proj.ApplyTx(readCtx, tx, result)
		})
	})
	return result, err
}

// The tenant metadata fence covers every certificate, not only this fingerprint.
// A previous append for another leaf may have won while its SQL transaction lost.
// Recover those recordings before advancing the shared metadata watermark; the
// next boot must still be able to replay every retained event in source order.
// The log cut is finite; caller cancellation and deadlines remain active.
func (o *Orchestrator) catchUpCertificateRecordingTx(ctx context.Context, tx pgx.Tx, tenantID, fingerprint string) error {
	_, _, err := o.catchUpCertificateRecordingAndLookupTx(ctx, tx, tenantID, fingerprint, "")
	return err
}

func (o *Orchestrator) catchUpCertificateRecordingAndLookupTx(ctx context.Context, tx pgx.Tx, tenantID, fingerprint, eventID string) (events.Event, bool, error) {
	head, err := o.store.CertificateRecordingHeadTx(ctx, tx, tenantID, fingerprint)
	if err != nil {
		return events.Event{}, false, err
	}
	if head.Exists && head.Sequence == 0 {
		return events.Event{}, false, store.ErrCertificateRecordingRebuildRequired
	}
	through, err := o.log.LastSequence(ctx)
	if err != nil {
		return events.Event{}, false, err
	}
	if head.Sequence > through {
		return events.Event{}, false, errors.New("orchestrator: certificate recording cursor is beyond retained log head")
	}
	lifetimeFloor, err := o.certificateRecordingLifetimeFloorTx(ctx, tx, tenantID, through)
	if err != nil {
		return events.Event{}, false, err
	}
	from := head.Sequence + 1
	if from <= lifetimeFloor {
		from = lifetimeFloor + 1
	}
	if from == 0 {
		return events.Event{}, false, errors.New("orchestrator: certificate recording cursor overflow")
	}
	page := make([]events.Event, 0, store.CertificateMetadataReceiptBatchLimit)
	pageBytes := 0
	flush := func() error {
		done, err := o.store.CertificateMetadataEventsAppliedTx(ctx, tx, tenantID, page)
		if err != nil {
			return err
		}
		for i, e := range page {
			if done[i] {
				continue
			}
			_, recording, err := projections.CertificateRecordingMaterial(e)
			if err != nil {
				return err
			}
			if !recording {
				return fmt.Errorf("%w: pending metadata event %d must project in order before a new recording", store.ErrCertificateRecordingRebuildRequired, e.Sequence)
			}
			if err := o.proj.ApplyTx(ctx, tx, e); err != nil {
				return err
			}
		}
		clear(page)
		page, pageBytes = page[:0], 0
		return nil
	}
	visit := func(e events.Event) error {
		if !sameCertificateRecordingTenant(e.TenantID, tenantID) {
			return nil
		}
		dependent, err := projections.CertificateMetadataEvent(e)
		if err != nil {
			return err
		}
		if !dependent {
			return nil
		}
		// Match ApplyTx: admit the schema, then verify the whole immutable
		// envelope against its completion receipt before decoding certificate
		// material again. Only an exact receipt can skip domain decoding;
		// flush still decodes every unapplied recording before projection.
		// Keep transport and memory bounded without replacing source history
		// with a maximum SQL sequence. Large envelopes get their own page.
		const maxPageBytes = 1 << 20
		if len(page) > 0 && pageBytes+len(e.Data) > maxPageBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		page = append(page, e)
		pageBytes += len(e.Data)
		if len(page) == cap(page) || pageBytes >= maxPageBytes {
			return flush()
		}
		return nil
	}
	var retained events.Event
	var found bool
	if eventID == "" {
		err = o.log.ReplayThrough(ctx, from, through, visit)
	} else {
		// Lookup and recovery inspect the same immutable cut under the tenant
		// metadata/privacy fences. Reuse decoded envelopes, not a SQL maximum
		// or a cross-command cache of previously verified history.
		retained, found, err = o.log.ReplayThroughAndLookup(ctx, from, through, eventID, visit)
	}
	if err != nil {
		return events.Event{}, false, err
	}
	if err := flush(); err != nil {
		return events.Event{}, false, err
	}
	if found && retained.Sequence <= lifetimeFloor {
		return events.Event{}, false, fmt.Errorf("%w: certificate command belongs to an earlier tenant registration", store.ErrIdempotencyConflict)
	}
	return retained, found, nil
}

// The caller already holds the certificate relation/metadata fence. Offboard
// must acquire that same fence before erasing the tenant; registration cannot
// replace an existing row. Read without a row/lifecycle lock: taking either here
// would invert offboard's lifecycle -> certificate order. The privacy barrier
// outside the transaction keeps the retained history generation fixed.
func (o *Orchestrator) certificateRecordingLifetimeFloorTx(ctx context.Context, tx pgx.Tx, tenantID string, through uint64) (uint64, error) {
	var registration int64
	var name string
	if err := tx.QueryRow(ctx, `SELECT event_seq,name FROM tenants WHERE tenant_id=$1`, tenantID).Scan(&registration, &name); err != nil {
		return 0, fmt.Errorf("%w: certificate recording requires a live tenant: %v", store.ErrCertificateRecordingRebuildRequired, err)
	}
	if registration < 0 {
		return 0, fmt.Errorf("%w: tenant registration is outside retained history", store.ErrCertificateRecordingRebuildRequired)
	}
	registrationSequence := uint64(registration)
	if registrationSequence > through {
		return 0, fmt.Errorf("%w: tenant registration is outside retained history", store.ErrCertificateRecordingRebuildRequired)
	}
	if registrationSequence > 0 {
		event, found, err := o.log.EventAtSequence(ctx, registrationSequence)
		if err != nil {
			return 0, err
		}
		if !found || event.Type != projections.EventTenantRegistered || !sameCertificateRecordingTenant(event.TenantID, tenantID) ||
			projections.ValidateSchemaVersion(event) != nil || validateTenantRegistrationPayload(event.Data, name) != nil {
			return 0, fmt.Errorf("%w: tenant registration has no matching retained envelope", store.ErrCertificateRecordingRebuildRequired)
		}
		if isDurableTenantRegistrationIdentity(event.ID) {
			return registrationSequence, nil
		}
	}
	// Legacy tenant.registered events also represented renames. Their latest
	// row sequence is not necessarily the beginning of a customer lifetime, so
	// retain same-lifetime recovery and locate the last explicit erase instead.
	// A zero-sequence SQL bootstrap is supported only without retained erasure.
	var floor uint64
	err := o.log.ReplayThrough(ctx, 1, through, func(event events.Event) error {
		if !sameCertificateRecordingTenant(event.TenantID, tenantID) || event.Type != projections.EventTenantOffboarded {
			return nil
		}
		if err := projections.ValidateSchemaVersion(event); err != nil {
			return err
		}
		if registrationSequence == 0 || event.Sequence >= registrationSequence {
			return fmt.Errorf("%w: retained offboard has no later live registration", store.ErrCertificateRecordingRebuildRequired)
		}
		floor = event.Sequence
		return nil
	})
	return floor, err
}

// SQL tenant keys are UUIDs. Recovery must compare the same UUID domain as the
// transaction lock, including an older event that used uppercase UUID spelling.
func sameCertificateRecordingTenant(left, right string) bool {
	a, err := uuid.Parse(left)
	if err != nil {
		return false
	}
	b, err := uuid.Parse(right)
	return err == nil && a == b
}

// Check and lock metadata before the irreversible append as well as before its
// projection. The actual retained head is a bound, never a guessed next sequence.
// A concurrent later writer can cause a conservative refusal; retry reads a new
// head. Unknown provenance requires explicit rebuild, with no new event appended.
func (o *Orchestrator) guardCertificateRecordingAppendTx(ctx context.Context, tx pgx.Tx, tenantID string, material store.Certificate) error {
	through, err := o.log.LastSequence(ctx)
	if err != nil {
		return err
	}
	// A first recording may be the first event after tenant bootstrap. Zero
	// still goes through the metadata fence: unknown writes and SQL state
	// ahead of the retained source are rejected before any append.
	return o.store.GuardCertificateRecordingMetadataTx(ctx, tx, tenantID, material.Fingerprint, material.ReplacesID, through)
}
