// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A208: a person places an S3 legal hold on one archive object and releases
// it; the outbox sets or clears it in the bucket and the read-back is recorded.
const (
	EventArchiveLegalHoldPlaced           = "archive.legal_hold.placed"
	EventArchiveLegalHoldReleaseRequested = "archive.legal_hold.release_requested"
	EventArchiveLegalHoldRecorded         = "archive.legal_hold.recorded"
)

// ArchiveLegalHoldPlaced is a hold on one object; the person is the actor.
type ArchiveLegalHoldPlaced struct {
	ID          string `json:"id"`
	Object      string `json:"object"`
	Reason      string `json:"reason"`
	ReportRunID string `json:"report_run_id,omitempty"`
}

// ArchiveLegalHoldRelease releases a hold.
type ArchiveLegalHoldRelease struct {
	ID string `json:"id"`
}

// ArchiveLegalHoldRecorded is what the bucket read back: applied, released
// or failed with the reason.
type ArchiveLegalHoldRecorded struct {
	ID     string    `json:"id"`
	Status string    `json:"status"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// ValidateArchiveLegalHold checks a placement.
func ValidateArchiveLegalHold(pl ArchiveLegalHoldPlaced) error {
	if pl.ID == "" || pl.Object == "" || len(pl.Object) > 1024 {
		return errors.New("an archive legal hold names its id and object")
	}
	if pl.Reason == "" || len(pl.Reason) > complianceReportLegalHoldReasonMax {
		return fmt.Errorf("a legal hold needs a reason of 1 to %d characters", complianceReportLegalHoldReasonMax)
	}
	return nil
}

func (p *Projector) applyArchiveLegalHoldTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventArchiveLegalHoldPlaced:
		var pl ArchiveLegalHoldPlaced
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if err := ValidateArchiveLegalHold(pl); err != nil {
			return true, fmt.Errorf("projections: %s: %w", e.Type, err)
		}
		return true, p.store.PlaceArchiveLegalHoldTx(ctx, tx, archiveLegalHoldFromEvent(e, pl))
	case EventArchiveLegalHoldReleaseRequested:
		var pl ArchiveLegalHoldRelease
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		return true, p.store.RequestArchiveLegalHoldReleaseTx(ctx, tx, e.TenantID, pl.ID, e.Time, e.Sequence)
	case EventArchiveLegalHoldRecorded:
		var pl ArchiveLegalHoldRecorded
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		switch pl.Status {
		case "applied", "released", "failed":
		default:
			return true, fmt.Errorf("projections: %s: status %q", e.Type, pl.Status)
		}
		return true, p.store.RecordArchiveLegalHoldOutcomeTx(ctx, tx, e.TenantID, pl.ID, pl.Status, pl.Detail, pl.At, e.Sequence)
	}
	return false, nil
}

func archiveLegalHoldFromEvent(e events.Event, pl ArchiveLegalHoldPlaced) store.ArchiveLegalHold {
	by := ""
	if e.Actor != nil {
		by = e.Actor.Subject
	}
	return store.ArchiveLegalHold{
		TenantID: e.TenantID, ID: pl.ID, Object: pl.Object, Reason: pl.Reason, ReportRunID: pl.ReportRunID,
		PlacedBy: by, PlacedAt: e.Time, EventSequence: e.Sequence,
	}
}
