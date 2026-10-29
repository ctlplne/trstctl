// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A208: a person's S3 legal hold on one archive object.

// ErrArchiveLegalHoldLinked refuses a direct storage release while its report
// remains held. After report release, its failed storage step can be retried.
var ErrArchiveLegalHoldLinked = errors.New("orchestrator: this storage hold belongs to a report's legal hold; release that hold")

// PlaceArchiveLegalHold records a person's legal hold on one archive object;
// its projection queues setting it in the bucket.
func (o *Orchestrator) PlaceArchiveLegalHold(ctx context.Context, tenantID, object, reason string) (store.ArchiveLegalHold, error) {
	pl := projections.ArchiveLegalHoldPlaced{ID: uuid.NewString(), Object: object, Reason: strings.TrimSpace(reason)}
	if err := projections.ValidateArchiveLegalHold(pl); err != nil {
		return store.ArchiveLegalHold{}, &InvalidComplianceReportHoldError{Reason: err.Error()}
	}
	if _, active, err := o.store.ActiveArchiveLegalHoldFor(ctx, tenantID, object); err != nil {
		return store.ArchiveLegalHold{}, err
	} else if active {
		return store.ArchiveLegalHold{}, store.ErrArchiveLegalHoldState
	}
	data, err := json.Marshal(pl)
	if err != nil {
		return store.ArchiveLegalHold{}, err
	}
	if _, err := o.emit(ctx, projections.EventArchiveLegalHoldPlaced, tenantID, data); err != nil {
		return store.ArchiveLegalHold{}, err
	}
	return o.store.GetArchiveLegalHold(ctx, tenantID, pl.ID)
}

// ReleaseArchiveLegalHold records a person releasing a hold; its projection
// queues clearing it in the bucket.
func (o *Orchestrator) ReleaseArchiveLegalHold(ctx context.Context, tenantID, id string) (store.ArchiveLegalHold, error) {
	hold, err := o.store.GetArchiveLegalHold(ctx, tenantID, id)
	if err != nil {
		return store.ArchiveLegalHold{}, err
	}
	if hold.ReportRunID != "" {
		run, err := o.store.GetComplianceReportRun(ctx, tenantID, hold.ReportRunID)
		if err != nil {
			return store.ArchiveLegalHold{}, err
		}
		if run.Retention.Held() {
			return store.ArchiveLegalHold{}, ErrArchiveLegalHoldLinked
		}
	}
	if hold.Status != "pending" && hold.Status != "applied" && hold.Status != "failed" {
		return store.ArchiveLegalHold{}, store.ErrArchiveLegalHoldState
	}
	if active, found, err := o.store.ActiveArchiveLegalHoldFor(ctx, tenantID, hold.Object); err != nil {
		return store.ArchiveLegalHold{}, err
	} else if found && active.ID != id {
		return store.ArchiveLegalHold{}, store.ErrArchiveLegalHoldState
	}
	data, err := json.Marshal(projections.ArchiveLegalHoldRelease{ID: id})
	if err != nil {
		return store.ArchiveLegalHold{}, err
	}
	if _, err := o.emit(ctx, projections.EventArchiveLegalHoldReleaseRequested, tenantID, data); err != nil {
		return store.ArchiveLegalHold{}, err
	}
	return o.store.GetArchiveLegalHold(ctx, tenantID, id)
}

// RecordArchiveLegalHoldOutcome records what the bucket read back after a
// hold was set or cleared: applied, released or failed with the reason.
func (o *Orchestrator) RecordArchiveLegalHoldOutcome(ctx context.Context, tenantID, id, status, detail string, at time.Time) error {
	data, err := json.Marshal(projections.ArchiveLegalHoldRecorded{ID: id, Status: status, Detail: detail, At: at.UTC()})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventArchiveLegalHoldRecorded, tenantID, data)
	return err
}
