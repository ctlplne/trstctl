// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
)

// A206: a person places or releases a legal hold on a completed report run's
// signed report, and the opt-in report retention removes an unheld report once
// it is older than the window.
const (
	EventComplianceReportLegalHoldPlaced         = "compliance.report_run.legal_hold_placed"
	EventComplianceReportLegalHoldReleased       = "compliance.report_run.legal_hold_released"
	EventComplianceReportArtifactExpiryRequested = "compliance.report_run.artifact_expiry_requested"
	EventComplianceReportArtifactExpired         = "compliance.report_run.artifact_expired"
	complianceReportLegalHoldReasonMax           = 512
	// EventComplianceReportArtifactExpiryDeferred records a removal the
	// archive's S3 Object Lock refused (A208).
	EventComplianceReportArtifactExpiryDeferred = "compliance.report_run.artifact_expiry_deferred"
)

// ComplianceReportLegalHold is a hold placed or released; the person is the
// event's actor. When the report is in an object store with S3 Object Lock,
// the same event holds (or releases) its object there too (A208).
type ComplianceReportLegalHold struct {
	RunID  string `json:"run_id"`
	Reason string `json:"reason,omitempty"`
	// StorageHoldID and StorageObject name the archive legal hold on the
	// report's object; empty when the archive cannot hold it.
	StorageHoldID string `json:"storage_hold_id,omitempty"`
	StorageObject string `json:"storage_object,omitempty"`
}

// ComplianceReportArtifactExpiry is a retention removal, requested or done.
type ComplianceReportArtifactExpiry struct {
	RunID  string `json:"run_id"`
	Digest string `json:"digest"`
	// RetentionSeconds is the window the run fell outside of.
	RetentionSeconds int64 `json:"retention_seconds"`
	// ExpiredAt is when the report was confirmed gone (expired events only).
	ExpiredAt *time.Time `json:"expired_at,omitempty"`
}

// ComplianceReportArtifactExpiryDeferred is a removal the archive's Object
// Lock refused: the retention asks again at LockedUntil (the retention's end,
// or a day later under a legal hold, which has no end of its own).
type ComplianceReportArtifactExpiryDeferred struct {
	RunID       string    `json:"run_id"`
	Digest      string    `json:"digest"`
	LockedUntil time.Time `json:"locked_until"`
	LegalHold   bool      `json:"legal_hold,omitempty"`
}

// ValidateComplianceReportLegalHold checks a hold event.
func ValidateComplianceReportLegalHold(placed bool, pl ComplianceReportLegalHold) error {
	if pl.RunID == "" {
		return errors.New("a legal hold names its report run")
	}
	if placed && (pl.Reason == "" || len(pl.Reason) > complianceReportLegalHoldReasonMax) {
		return fmt.Errorf("a legal hold needs a reason of 1 to %d characters", complianceReportLegalHoldReasonMax)
	}
	return nil
}

func (p *Projector) applyComplianceReportRetentionTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventComplianceReportLegalHoldPlaced, EventComplianceReportLegalHoldReleased:
		var pl ComplianceReportLegalHold
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		placed := e.Type == EventComplianceReportLegalHoldPlaced
		if err := ValidateComplianceReportLegalHold(placed, pl); err != nil {
			return true, fmt.Errorf("projections: %s: %w", e.Type, err)
		}
		by := ""
		if e.Actor != nil {
			by = e.Actor.Subject
		}
		if err := p.store.ApplyComplianceReportLegalHoldTx(ctx, tx, e.TenantID, pl.RunID, placed, pl.Reason, by, e.Time, e.Sequence); err != nil {
			return true, err
		}
		if pl.StorageHoldID == "" {
			return true, nil
		}
		if placed {
			err := p.store.PlaceArchiveLegalHoldTx(ctx, tx, archiveLegalHoldFromEvent(e, ArchiveLegalHoldPlaced{
				ID: pl.StorageHoldID, Object: pl.StorageObject, Reason: pl.Reason, ReportRunID: pl.RunID,
			}))
			return true, err
		}
		// The report's hold is released whatever its storage hold's state.
		return true, p.store.RequestArchiveLegalHoldReleaseTx(ctx, tx, e.TenantID, pl.StorageHoldID, e.Time, e.Sequence)
	case EventComplianceReportArtifactExpiryRequested:
		// The request queues the removal in this transaction (AN-6); the
		// report is recorded expired only when the removal is confirmed.
		var pl ComplianceReportArtifactExpiry
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.RunID == "" || pl.Digest == "" {
			return true, fmt.Errorf("projections: %s needs a run and a digest", e.Type)
		}
		return true, p.store.ApplyComplianceReportArtifactExpiryRequestedTx(ctx, tx, e.TenantID, pl.RunID, e.Time, e.Sequence, e.Data)
	case EventComplianceReportArtifactExpiryDeferred:
		var pl ComplianceReportArtifactExpiryDeferred
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.RunID == "" || pl.LockedUntil.IsZero() {
			return true, fmt.Errorf("projections: %s needs a run and a time", e.Type)
		}
		return true, p.store.ApplyComplianceReportArtifactExpiryDeferredTx(ctx, tx, e.TenantID, pl.RunID, pl.LockedUntil, e.Sequence)
	case EventComplianceReportArtifactExpired:
		var pl ComplianceReportArtifactExpiry
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.RunID == "" || pl.ExpiredAt == nil {
			return true, fmt.Errorf("projections: %s needs a run and a time", e.Type)
		}
		return true, p.store.ApplyComplianceReportArtifactExpiredTx(ctx, tx, e.TenantID, pl.RunID, *pl.ExpiredAt, e.Sequence)
	}
	return false, nil
}
