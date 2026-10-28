// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// RecordCertificateSCTWithEventID keeps what a CT log answered for one
// submission (A213) under an id derived from the delivery, so a retried
// delivery cannot record a different answer.
func (o *Orchestrator) RecordCertificateSCTWithEventID(ctx context.Context, tenantID, eventID string,
	sct projections.CertificateSCTRecorded) error {
	if err := projections.ValidateCertificateSCTRecorded(sct); err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}
	return o.recordExactEvent(ctx, tenantID, eventID, projections.EventCertificateSCTRecorded, sct)
}

// RecordCertificateSCTInclusionWithEventID keeps what an inclusion check
// found for a submission's SCT.
func (o *Orchestrator) RecordCertificateSCTInclusionWithEventID(ctx context.Context, tenantID, eventID string,
	inclusion projections.CertificateSCTInclusion) error {
	return o.recordExactEvent(ctx, tenantID, eventID, projections.EventCertificateSCTInclusion, inclusion)
}

// recordExactEvent appends one event under a caller-derived id and projects
// it in the same tenant command; a retry with the same id must carry the same
// bytes.
func (o *Orchestrator) recordExactEvent(ctx context.Context, tenantID, eventID, eventType string, payload any) error {
	if o == nil || o.log == nil || strings.TrimSpace(eventID) == "" {
		return errors.New("orchestrator: an exact event needs an event id")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		event, err := o.log.Append(ctx, events.Event{ID: eventID, Type: eventType, TenantID: tenantID, Data: raw})
		if err != nil {
			return err
		}
		if event.ID != eventID || event.Type != eventType || event.TenantID != tenantID || !bytes.Equal(event.Data, raw) {
			return fmt.Errorf("%w: %s differs from the retained event", store.ErrIdempotencyConflict, eventType)
		}
		return o.proj.ApplyTx(ctx, tx, event)
	})
}

// RecordCertificateDERRecoveredWithEventID gives an inventory row without
// certificate bytes the bytes of its certificate (A215), under an id derived
// from where they were found.
func (o *Orchestrator) RecordCertificateDERRecoveredWithEventID(ctx context.Context, tenantID, eventID string,
	recovered projections.CertificateDERRecovered) error {
	if err := projections.ValidateCertificateDERRecovered(recovered); err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}
	return o.recordExactEvent(ctx, tenantID, eventID, projections.EventCertificateDERRecovered, recovered)
}

// RecordCARolloverDraftedWithEventID records a drafted CA rollover (A216)
// under an id derived from the authority and band, so one band drafts once.
func (o *Orchestrator) RecordCARolloverDraftedWithEventID(ctx context.Context, tenantID, eventID string,
	drafted projections.CARolloverDrafted) error {
	if err := projections.ValidateCARolloverDrafted(drafted); err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}
	return o.recordExactEvent(ctx, tenantID, eventID, projections.EventCARolloverDrafted, drafted)
}
