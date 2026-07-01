package orchestrator

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// UpsertSecretRotationSchedule records a tenant scheduled static-credential
// rotation as an immutable event. The relational schedule row is a projection, so
// replay rebuilds the cadence and last-run metadata.
func (o *Orchestrator) UpsertSecretRotationSchedule(ctx context.Context, tenantID string, in store.SecretRotationSchedule) (store.SecretRotationSchedule, error) {
	id := in.ID
	if id == "" {
		id = uuid.NewString()
	}
	payload, err := json.Marshal(projections.SecretRotationScheduleUpserted{
		ID: id, Name: strings.TrimSpace(in.Name), Provider: strings.TrimSpace(in.Provider),
		Key: strings.TrimSpace(in.Key), OldRef: strings.TrimSpace(in.OldRef),
		IntervalSeconds: in.IntervalSeconds, Enabled: in.Enabled, NextRunAt: in.NextRunAt,
	})
	if err != nil {
		return store.SecretRotationSchedule{}, err
	}
	ev, err := o.emit(ctx, projections.EventSecretRotationScheduleUpserted, tenantID, payload)
	if err != nil {
		return store.SecretRotationSchedule{}, err
	}
	nextRunAt := in.NextRunAt
	if nextRunAt.IsZero() {
		nextRunAt = ev.Time.Add(time.Duration(in.IntervalSeconds) * time.Second)
	}
	return store.SecretRotationSchedule{
		ID: id, TenantID: tenantID, Name: strings.TrimSpace(in.Name),
		Provider: strings.TrimSpace(in.Provider), Key: strings.TrimSpace(in.Key),
		OldRef: strings.TrimSpace(in.OldRef), IntervalSeconds: in.IntervalSeconds,
		Enabled: in.Enabled, NextRunAt: nextRunAt, CreatedAt: ev.Time, UpdatedAt: ev.Time,
	}, nil
}

// RecordSecretRotationScheduleRun records the outcome of one due scheduled
// rotation. It stores metadata and refs only; credential values stay inside the
// configured rotator/provider.
func (o *Orchestrator) RecordSecretRotationScheduleRun(ctx context.Context, tenantID string, in store.SecretRotationScheduleRun) (store.SecretRotationScheduleRun, error) {
	runID := in.RunID
	if runID == "" {
		runID = uuid.NewString()
	}
	payload, err := json.Marshal(projections.SecretRotationScheduleRan{
		ScheduleID: in.ScheduleID, RunID: runID, Status: in.Status,
		NewRef: in.NewRef, Error: in.Error,
	})
	if err != nil {
		return store.SecretRotationScheduleRun{}, err
	}
	ev, err := o.emit(ctx, projections.EventSecretRotationScheduleRan, tenantID, payload)
	if err != nil {
		return store.SecretRotationScheduleRun{}, err
	}
	return store.SecretRotationScheduleRun{
		TenantID: tenantID, ScheduleID: in.ScheduleID, RunID: runID,
		Status: in.Status, NewRef: in.NewRef, Error: in.Error, RanAt: ev.Time,
	}, nil
}
