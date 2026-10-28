// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A206: a person holds a completed report run's signed report, and the opt-in
// report retention removes an unheld report once it is older than its window.

// ErrComplianceReportHoldState refuses a hold on a run that is not completed,
// is already held or has expired, and a release of a run that is not held.
var ErrComplianceReportHoldState = errors.New("orchestrator: the report run cannot take that hold change")

// PlaceComplianceReportLegalHold holds a completed run's report until a person
// releases it; the report retention leaves it.
func (o *Orchestrator) PlaceComplianceReportLegalHold(ctx context.Context, tenantID, runID, reason string) (store.ComplianceReportRun, error) {
	reason = strings.TrimSpace(reason)
	pl := projections.ComplianceReportLegalHold{RunID: runID, Reason: reason}
	if err := projections.ValidateComplianceReportLegalHold(true, pl); err != nil {
		return store.ComplianceReportRun{}, &InvalidComplianceReportHoldError{Reason: err.Error()}
	}
	return o.withComplianceReportRun(ctx, tenantID, runID, func(run store.ComplianceReportRun) (store.ComplianceReportRun, error) {
		if run.Status != "completed" || run.Retention.Held() || run.Retention.ArtifactExpiredAt != nil {
			return store.ComplianceReportRun{}, ErrComplianceReportHoldState
		}
		return o.emitComplianceReportRetention(ctx, tenantID, runID, projections.EventComplianceReportLegalHoldPlaced, pl)
	})
}

// ReleaseComplianceReportLegalHold releases a held run's report back to the
// report retention.
func (o *Orchestrator) ReleaseComplianceReportLegalHold(ctx context.Context, tenantID, runID string) (store.ComplianceReportRun, error) {
	return o.withComplianceReportRun(ctx, tenantID, runID, func(run store.ComplianceReportRun) (store.ComplianceReportRun, error) {
		if !run.Retention.Held() {
			return store.ComplianceReportRun{}, ErrComplianceReportHoldState
		}
		return o.emitComplianceReportRetention(ctx, tenantID, runID, projections.EventComplianceReportLegalHoldReleased,
			projections.ComplianceReportLegalHold{RunID: runID})
	})
}

// ErrComplianceReportBusy is a hold change that met the report retention
// removing the same run; retrying settles it.
var ErrComplianceReportBusy = errors.New("orchestrator: the report run is being changed; retry")

// withComplianceReportRun runs a hold change under the run's lock, the lock the
// retention's removal takes, so a person's hold and a removal never interleave.
func (o *Orchestrator) withComplianceReportRun(ctx context.Context, tenantID, runID string, fn func(store.ComplianceReportRun) (store.ComplianceReportRun, error)) (store.ComplianceReportRun, error) {
	run, err := o.store.GetComplianceReportRun(ctx, tenantID, runID)
	if err != nil {
		return store.ComplianceReportRun{}, err
	}
	var out store.ComplianceReportRun
	acquired, err := o.store.WithComplianceReportRunLock(ctx, tenantID, run.ScheduleID, run.DueAt, func() error {
		current, err := o.store.GetComplianceReportRun(ctx, tenantID, runID)
		if err != nil {
			return err
		}
		out, err = fn(current)
		return err
	})
	if err != nil {
		return store.ComplianceReportRun{}, err
	}
	if !acquired {
		return store.ComplianceReportRun{}, ErrComplianceReportBusy
	}
	return out, nil
}

// RequestComplianceReportArtifactExpiry records that the retention removes a
// run's report; its projection queues the removal in the same transaction.
func (o *Orchestrator) RequestComplianceReportArtifactExpiry(ctx context.Context, run store.ComplianceReportRun, retention time.Duration) error {
	data, err := json.Marshal(projections.ComplianceReportArtifactExpiry{
		RunID: run.ID, Digest: run.ArtifactDigest, RetentionSeconds: int64(retention / time.Second),
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventComplianceReportArtifactExpiryRequested, run.TenantID, data)
	return err
}

// DeferComplianceReportArtifactExpiry records that the archive's Object Lock
// protects a run's report, so the retention asks again at lockedUntil.
func (o *Orchestrator) DeferComplianceReportArtifactExpiry(ctx context.Context, tenantID, runID, digest string, lockedUntil time.Time, legalHold bool) error {
	data, err := json.Marshal(projections.ComplianceReportArtifactExpiryDeferred{
		RunID: runID, Digest: digest, LockedUntil: lockedUntil.UTC(), LegalHold: legalHold,
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventComplianceReportArtifactExpiryDeferred, tenantID, data)
	return err
}

// RecordComplianceReportArtifactExpired records that a run's report is
// confirmed gone.
func (o *Orchestrator) RecordComplianceReportArtifactExpired(ctx context.Context, tenantID, runID, digest string, retention time.Duration, at time.Time) error {
	at = at.UTC()
	data, err := json.Marshal(projections.ComplianceReportArtifactExpiry{
		RunID: runID, Digest: digest, RetentionSeconds: int64(retention / time.Second), ExpiredAt: &at,
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventComplianceReportArtifactExpired, tenantID, data)
	return err
}

func (o *Orchestrator) emitComplianceReportRetention(ctx context.Context, tenantID, runID, eventType string, pl projections.ComplianceReportLegalHold) (store.ComplianceReportRun, error) {
	data, err := json.Marshal(pl)
	if err != nil {
		return store.ComplianceReportRun{}, err
	}
	if _, err := o.emit(ctx, eventType, tenantID, data); err != nil {
		if errors.Is(err, store.ErrComplianceReportRetentionState) {
			return store.ComplianceReportRun{}, ErrComplianceReportHoldState
		}
		return store.ComplianceReportRun{}, err
	}
	return o.store.GetComplianceReportRun(ctx, tenantID, runID)
}

// InvalidComplianceReportHoldError is a hold the projection would refuse.
type InvalidComplianceReportHoldError struct{ Reason string }

func (e *InvalidComplianceReportHoldError) Error() string { return "orchestrator: " + e.Reason }
