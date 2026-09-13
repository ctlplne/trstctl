// SPDX-License-Identifier: MPL-2.0

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
			if err := o.catchUpCertificateRecordingTx(readCtx, tx, next.TenantID, material.Fingerprint); err != nil {
				return err
			}
			if err := o.store.ValidateCertificateIssuanceBindingTx(readCtx, tx, next.TenantID, material); err != nil {
				return err
			}
			if next.ID != "" {
				retained, found, err := o.log.EventByID(readCtx, next.ID)
				if err != nil {
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
			}
			if err := o.guardCertificateRecordingAppendTx(readCtx, tx, next.TenantID, material); err != nil {
				return err
			}
			var err error
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
	head, err := o.store.CertificateRecordingHeadTx(ctx, tx, tenantID, fingerprint)
	if err != nil {
		return err
	}
	if head.Exists && head.Sequence == 0 {
		return store.ErrCertificateRecordingRebuildRequired
	}
	through, err := o.log.LastSequence(ctx)
	if err != nil {
		return err
	}
	if head.Sequence > through {
		return errors.New("orchestrator: certificate recording cursor is beyond retained log head")
	}
	from := head.Sequence + 1
	if from == 0 {
		return errors.New("orchestrator: certificate recording cursor overflow")
	}
	return o.log.ReplayThrough(ctx, from, through, func(e events.Event) error {
		if !sameCertificateRecordingTenant(e.TenantID, tenantID) {
			return nil
		}
		dependent, err := projections.CertificateMetadataEvent(e)
		if err != nil {
			return err
		}
		if dependent {
			_, recording, err := projections.CertificateRecordingMaterial(e)
			if err != nil {
				return err
			}
			if !recording {
				done, err := o.store.CertificateMetadataEventAppliedTx(ctx, tx, e)
				if err != nil {
					return err
				}
				if !done {
					return fmt.Errorf("%w: pending metadata event %d must project in order before a new recording", store.ErrCertificateRecordingRebuildRequired, e.Sequence)
				}
			}
		}
		_, recording, err := projections.CertificateRecordingMaterial(e)
		if err != nil {
			return err
		}
		if !recording {
			return nil
		}
		return o.proj.ApplyTx(ctx, tx, e)
	})
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
	if through == 0 {
		return errors.New("orchestrator: certificate append requires retained tenant history")
	}
	return o.store.GuardCertificateRecordingMetadataTx(ctx, tx, tenantID, material.Fingerprint, material.ReplacesID, through)
}
