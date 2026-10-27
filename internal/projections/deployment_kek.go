// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A198: the deployment KEK's lifecycle. A served rotation records each step as
// a full snapshot in the operator tenant's history; the projection keeps the
// deployment-wide row every tenant fence reads. The wrapped keys ride in every
// snapshot (only the operator's wrapper opens them), so replaying the history
// restores a rotation with both generations openable.
const (
	EventDeploymentKEKRotationStarted    = "deployment.kek.rotation_started"
	EventDeploymentKEKRotationProgressed = "deployment.kek.rotation_progressed"
	EventDeploymentKEKRotationCompleted  = "deployment.kek.rotation_completed"
	EventDeploymentKEKRotationFailed     = "deployment.kek.rotation_failed"
)

// DeploymentKEKSnapshot is the payload of every deployment.kek.* event.
type DeploymentKEKSnapshot struct {
	DomainID               string     `json:"domain_id"`
	Generation             int64      `json:"generation"`
	WrapperKind            string     `json:"wrapper_kind,omitempty"`
	WrapperID              string     `json:"wrapper_id,omitempty"`
	WrappedKEK             []byte     `json:"wrapped_kek,omitempty"`
	NextGeneration         int64      `json:"next_generation,omitempty"`
	NextWrapperKind        string     `json:"next_wrapper_kind,omitempty"`
	NextWrapperID          string     `json:"next_wrapper_id,omitempty"`
	NextWrappedKEK         []byte     `json:"next_wrapped_kek,omitempty"`
	OperationID            string     `json:"operation_id"`
	OperationStatus        string     `json:"operation_status"`
	Stage                  string     `json:"stage"`
	ProgressCursor         string     `json:"progress_cursor,omitempty"`
	TenantsTotal           int64      `json:"tenants_total"`
	TenantsDone            int64      `json:"tenants_done"`
	ContainersRewrapped    int64      `json:"containers_rewrapped"`
	HistoryEventsRewrapped int64      `json:"history_events_rewrapped"`
	FilesRewrapped         int64      `json:"files_rewrapped"`
	ContainersVerified     int64      `json:"containers_verified"`
	VerifyPasses           int64      `json:"verify_passes"`
	VerifyStragglers       int64      `json:"verify_stragglers"`
	PreviousGeneration     int64      `json:"previous_generation"`
	StartedAt              *time.Time `json:"started_at,omitempty"`
	VerifiedAt             *time.Time `json:"verified_at,omitempty"`
	RotatedAt              *time.Time `json:"rotated_at,omitempty"`
	LastErrorCode          string     `json:"last_error_code,omitempty"`
	LastError              string     `json:"last_error,omitempty"`
	CreatedAt              time.Time  `json:"created_at,omitempty"`
	UpdatedAt              time.Time  `json:"updated_at,omitempty"`
}

// DeploymentKEKSnapshotFrom is the event payload for a deployment KEK state.
func DeploymentKEKSnapshotFrom(d store.DeploymentKEKDomain) DeploymentKEKSnapshot {
	return DeploymentKEKSnapshot{
		DomainID: d.DomainID, Generation: d.Generation,
		WrapperKind: d.WrapperKind, WrapperID: d.WrapperID,
		WrappedKEK:     append([]byte(nil), d.WrappedKEK...),
		NextGeneration: d.NextGeneration, NextWrapperKind: d.NextWrapperKind, NextWrapperID: d.NextWrapperID,
		NextWrappedKEK: append([]byte(nil), d.NextWrappedKEK...),
		OperationID:    d.OperationID, OperationStatus: d.OperationStatus, Stage: d.Stage,
		ProgressCursor: d.ProgressCursor, TenantsTotal: d.TenantsTotal, TenantsDone: d.TenantsDone,
		ContainersRewrapped: d.ContainersRewrapped, HistoryEventsRewrapped: d.HistoryEventsRewrapped,
		FilesRewrapped: d.FilesRewrapped, ContainersVerified: d.ContainersVerified,
		VerifyPasses: d.VerifyPasses, VerifyStragglers: d.VerifyStragglers, PreviousGeneration: d.PreviousGeneration,
		StartedAt: d.StartedAt, VerifiedAt: d.VerifiedAt, RotatedAt: d.RotatedAt,
		LastErrorCode: d.LastErrorCode, LastError: d.LastError,
		CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
}

func validateDeploymentKEKSnapshot(eventType string, pl DeploymentKEKSnapshot) error {
	if _, err := uuid.Parse(pl.DomainID); err != nil {
		return fmt.Errorf("projections: %s needs a domain id", eventType)
	}
	switch {
	case pl.Generation < 0 || pl.NextGeneration < 0:
		return fmt.Errorf("projections: %s carries a negative generation", eventType)
	case pl.Generation == 0 && (pl.WrapperKind != "" || pl.WrapperID != "" || len(pl.WrappedKEK) > 0):
		return fmt.Errorf("projections: %s gives generation 0 (the key file) a wrapper", eventType)
	case pl.Generation > 0 && (strings.TrimSpace(pl.WrapperKind) == "" || strings.TrimSpace(pl.WrapperID) == "" || len(pl.WrappedKEK) == 0):
		return fmt.Errorf("projections: %s carries a generation without its wrapper and wrapped key", eventType)
	case pl.NextGeneration > 0 && (pl.NextGeneration != pl.Generation+1 ||
		strings.TrimSpace(pl.NextWrapperKind) == "" || strings.TrimSpace(pl.NextWrapperID) == "" || len(pl.NextWrappedKEK) == 0):
		return fmt.Errorf("projections: %s carries an incomplete next generation; it must be generation+1 with a wrapper and wrapped key", eventType)
	case pl.NextGeneration == 0 && (pl.NextWrapperKind != "" || pl.NextWrapperID != "" || len(pl.NextWrappedKEK) > 0):
		return fmt.Errorf("projections: %s carries a next wrapper without a next generation", eventType)
	case strings.TrimSpace(pl.OperationID) == "":
		return fmt.Errorf("projections: %s needs an operation id", eventType)
	}
	switch eventType {
	case EventDeploymentKEKRotationStarted, EventDeploymentKEKRotationProgressed:
		if pl.NextGeneration == 0 || pl.OperationStatus != store.DeploymentKEKOperationRunning ||
			!oneOf(pl.Stage, store.DeploymentKEKStageSettling, store.DeploymentKEKStageHotState,
				store.DeploymentKEKStageHistory, store.DeploymentKEKStageFiles, store.DeploymentKEKStageVerify) {
			return fmt.Errorf("projections: %s must carry a running rotation to the next generation", eventType)
		}
	case EventDeploymentKEKRotationFailed:
		if pl.NextGeneration == 0 || pl.OperationStatus != store.DeploymentKEKOperationFailed || pl.LastErrorCode == "" {
			return fmt.Errorf("projections: %s must carry a failed rotation and its reason", eventType)
		}
	case EventDeploymentKEKRotationCompleted:
		if pl.NextGeneration != 0 || pl.Generation < 1 || pl.OperationStatus != store.DeploymentKEKOperationCompleted ||
			pl.Stage != store.DeploymentKEKStageCompleted || pl.RotatedAt == nil || pl.VerifiedAt == nil {
			return fmt.Errorf("projections: %s must promote a verified next generation", eventType)
		}
	default:
		return fmt.Errorf("projections: %s is not a deployment KEK event", eventType)
	}
	return nil
}

func (p *Projector) applyDeploymentKEKSnapshotTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	var pl DeploymentKEKSnapshot
	if err := decode(e, &pl); err != nil {
		return err
	}
	if e.ID == "" || e.Time.IsZero() || e.Sequence == 0 {
		return fmt.Errorf("projections: %s requires immutable event id, time, and positive stream-sequence evidence", e.Type)
	}
	if err := validateDeploymentKEKSnapshot(e.Type, pl); err != nil {
		return err
	}
	createdAt, updatedAt := pl.CreatedAt, pl.UpdatedAt
	if createdAt.IsZero() {
		createdAt = e.Time
	}
	if updatedAt.IsZero() {
		updatedAt = e.Time
	}
	actor := ""
	if e.Actor != nil {
		actor = e.Actor.Subject
	}
	at := e.Time
	return p.store.ApplyDeploymentKEKSnapshotTx(ctx, tx, store.DeploymentKEKDomain{
		DomainID: pl.DomainID, Generation: pl.Generation,
		WrapperKind: pl.WrapperKind, WrapperID: pl.WrapperID, WrappedKEK: pl.WrappedKEK,
		NextGeneration: pl.NextGeneration, NextWrapperKind: pl.NextWrapperKind,
		NextWrapperID: pl.NextWrapperID, NextWrappedKEK: pl.NextWrappedKEK,
		OperationID: pl.OperationID, OperationStatus: pl.OperationStatus, Stage: pl.Stage,
		ProgressCursor: pl.ProgressCursor, TenantsTotal: pl.TenantsTotal, TenantsDone: pl.TenantsDone,
		ContainersRewrapped: pl.ContainersRewrapped, HistoryEventsRewrapped: pl.HistoryEventsRewrapped,
		FilesRewrapped: pl.FilesRewrapped, ContainersVerified: pl.ContainersVerified,
		VerifyPasses: pl.VerifyPasses, VerifyStragglers: pl.VerifyStragglers, PreviousGeneration: pl.PreviousGeneration,
		StartedAt: pl.StartedAt, VerifiedAt: pl.VerifiedAt, RotatedAt: pl.RotatedAt,
		LastErrorCode: pl.LastErrorCode, LastError: pl.LastError,
		OperatorTenantID:      e.TenantID,
		LastTransitionEventID: e.ID, LastTransitionType: e.Type, LastTransitionActor: actor,
		LastTransitionAt: &at, LastTransitionSequence: e.Sequence,
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	})
}
