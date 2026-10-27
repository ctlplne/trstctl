// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Deployment KEK rotation stages and statuses (A198).
const (
	DeploymentKEKStageSettling  = "settling"
	DeploymentKEKStageHotState  = "hot_state"
	DeploymentKEKStageHistory   = "history"
	DeploymentKEKStageFiles     = "files"
	DeploymentKEKStageVerify    = "verify"
	DeploymentKEKStageCompleted = "completed"

	DeploymentKEKOperationRunning   = "running"
	DeploymentKEKOperationFailed    = "failed"
	DeploymentKEKOperationCompleted = "completed"
)

// deploymentKEKLockKey serializes deployment KEK transitions across replicas.
const deploymentKEKLockKey = "trstctl.deployment-kek"

// DeploymentKEKDomain is the event-derived state of the deployment KEK's
// generations (A198). Generation 0 is the local key file; a later generation
// is a key held under an operator wrapper, of which only WrappedKEK is stored.
// The Next* fields exist only while a rotation to Generation+1 runs, and new
// data is wrapped under the next generation from the moment it is recorded.
type DeploymentKEKDomain struct {
	DomainID               string
	Generation             int64
	WrapperKind            string
	WrapperID              string
	WrappedKEK             []byte
	NextGeneration         int64
	NextWrapperKind        string
	NextWrapperID          string
	NextWrappedKEK         []byte
	OperationID            string
	OperationStatus        string
	Stage                  string
	ProgressCursor         string
	TenantsTotal           int64
	TenantsDone            int64
	ContainersRewrapped    int64
	HistoryEventsRewrapped int64
	FilesRewrapped         int64
	ContainersVerified     int64
	VerifyPasses           int64
	VerifyStragglers       int64
	PreviousGeneration     int64
	StartedAt              *time.Time
	VerifiedAt             *time.Time
	RotatedAt              *time.Time
	LastErrorCode          string
	LastError              string
	OperatorTenantID       string
	LastTransitionEventID  string
	LastTransitionType     string
	LastTransitionActor    string
	LastTransitionAt       *time.Time
	LastTransitionSequence uint64
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// Rotating reports whether a rotation to the next generation is recorded and
// not yet complete.
func (d DeploymentKEKDomain) Rotating() bool { return d.NextGeneration > 0 }

// ApplyDeploymentKEKSnapshotTx projects one deployment.kek.* event snapshot.
// The event sequence is a monotonic guard, so replaying the operator tenant's
// history (a rebuild, a restore) never moves the row backwards.
func (s *Store) ApplyDeploymentKEKSnapshotTx(ctx context.Context, tx pgx.Tx, d DeploymentKEKDomain) error {
	if d.DomainID == "" {
		return errors.New("store: a deployment KEK snapshot needs its domain id")
	}
	// An absent wrapped key is NULL, never empty (the table's checks accept
	// exactly absent or exactly present).
	var wrapped, nextWrapped any
	if len(d.WrappedKEK) > 0 {
		wrapped = d.WrappedKEK
	}
	if len(d.NextWrappedKEK) > 0 {
		nextWrapped = d.NextWrappedKEK
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO public.deployment_kek_domain
		        (singleton, domain_id, generation, wrapper_kind, wrapper_id, wrapped_kek,
		         next_generation, next_wrapper_kind, next_wrapper_id, next_wrapped_kek,
		         operation_id, operation_status, stage, progress_cursor,
		         tenants_total, tenants_done, containers_rewrapped, history_events_rewrapped,
		         files_rewrapped, containers_verified, verify_passes, verify_stragglers,
		         previous_generation, started_at, verified_at, rotated_at, last_error_code, last_error,
		         operator_tenant_id, last_transition_event_id, last_transition_type,
		         last_transition_actor, last_transition_at, last_transition_sequence,
		         created_at, updated_at)
		 VALUES (true, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
		         $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29,
		         $30, $31, $32, $33, $34, $35)
		 ON CONFLICT (singleton) DO UPDATE SET
		     domain_id = EXCLUDED.domain_id,
		     generation = EXCLUDED.generation,
		     wrapper_kind = EXCLUDED.wrapper_kind,
		     wrapper_id = EXCLUDED.wrapper_id,
		     wrapped_kek = EXCLUDED.wrapped_kek,
		     next_generation = EXCLUDED.next_generation,
		     next_wrapper_kind = EXCLUDED.next_wrapper_kind,
		     next_wrapper_id = EXCLUDED.next_wrapper_id,
		     next_wrapped_kek = EXCLUDED.next_wrapped_kek,
		     operation_id = EXCLUDED.operation_id,
		     operation_status = EXCLUDED.operation_status,
		     stage = EXCLUDED.stage,
		     progress_cursor = EXCLUDED.progress_cursor,
		     tenants_total = EXCLUDED.tenants_total,
		     tenants_done = EXCLUDED.tenants_done,
		     containers_rewrapped = EXCLUDED.containers_rewrapped,
		     history_events_rewrapped = EXCLUDED.history_events_rewrapped,
		     files_rewrapped = EXCLUDED.files_rewrapped,
		     containers_verified = EXCLUDED.containers_verified,
		     verify_passes = EXCLUDED.verify_passes,
		     verify_stragglers = EXCLUDED.verify_stragglers,
		     previous_generation = EXCLUDED.previous_generation,
		     started_at = EXCLUDED.started_at,
		     verified_at = EXCLUDED.verified_at,
		     rotated_at = EXCLUDED.rotated_at,
		     last_error_code = EXCLUDED.last_error_code,
		     last_error = EXCLUDED.last_error,
		     operator_tenant_id = EXCLUDED.operator_tenant_id,
		     last_transition_event_id = EXCLUDED.last_transition_event_id,
		     last_transition_type = EXCLUDED.last_transition_type,
		     last_transition_actor = EXCLUDED.last_transition_actor,
		     last_transition_at = EXCLUDED.last_transition_at,
		     last_transition_sequence = EXCLUDED.last_transition_sequence,
		     created_at = public.deployment_kek_domain.created_at,
		     updated_at = EXCLUDED.updated_at
		 WHERE EXCLUDED.last_transition_sequence > public.deployment_kek_domain.last_transition_sequence`,
		d.DomainID, d.Generation, d.WrapperKind, d.WrapperID, wrapped,
		d.NextGeneration, d.NextWrapperKind, d.NextWrapperID, nextWrapped,
		d.OperationID, d.OperationStatus, d.Stage, d.ProgressCursor,
		d.TenantsTotal, d.TenantsDone, d.ContainersRewrapped, d.HistoryEventsRewrapped,
		d.FilesRewrapped, d.ContainersVerified, d.VerifyPasses, d.VerifyStragglers, d.PreviousGeneration,
		d.StartedAt, d.VerifiedAt, d.RotatedAt, d.LastErrorCode, d.LastError,
		d.OperatorTenantID, d.LastTransitionEventID, d.LastTransitionType,
		d.LastTransitionActor, d.LastTransitionAt,
		int64(d.LastTransitionSequence), // #nosec G115 -- event sequence fits int64 by construction; the column is a Postgres bigint (CWE-190)
		d.CreatedAt, d.UpdatedAt)
	return err
}

const deploymentKEKColumns = `domain_id::text, generation, wrapper_kind, wrapper_id, wrapped_kek,
	next_generation, next_wrapper_kind, next_wrapper_id, next_wrapped_kek,
	operation_id, operation_status, stage, progress_cursor,
	tenants_total, tenants_done, containers_rewrapped, history_events_rewrapped,
	files_rewrapped, containers_verified, verify_passes, verify_stragglers, previous_generation,
	started_at, verified_at, rotated_at, last_error_code, last_error,
	operator_tenant_id, last_transition_event_id, last_transition_type,
	last_transition_actor, last_transition_at, last_transition_sequence,
	created_at, updated_at`

func scanDeploymentKEKDomain(row pgx.Row) (DeploymentKEKDomain, bool, error) {
	var (
		d        DeploymentKEKDomain
		sequence int64
	)
	err := row.Scan(&d.DomainID, &d.Generation, &d.WrapperKind, &d.WrapperID, &d.WrappedKEK,
		&d.NextGeneration, &d.NextWrapperKind, &d.NextWrapperID, &d.NextWrappedKEK,
		&d.OperationID, &d.OperationStatus, &d.Stage, &d.ProgressCursor,
		&d.TenantsTotal, &d.TenantsDone, &d.ContainersRewrapped, &d.HistoryEventsRewrapped,
		&d.FilesRewrapped, &d.ContainersVerified, &d.VerifyPasses, &d.VerifyStragglers, &d.PreviousGeneration,
		&d.StartedAt, &d.VerifiedAt, &d.RotatedAt, &d.LastErrorCode, &d.LastError,
		&d.OperatorTenantID, &d.LastTransitionEventID, &d.LastTransitionType,
		&d.LastTransitionActor, &d.LastTransitionAt, &sequence,
		&d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeploymentKEKDomain{}, false, nil
	}
	if err != nil {
		return DeploymentKEKDomain{}, false, err
	}
	d.LastTransitionSequence = uint64(sequence) // #nosec G115 -- the column holds a non-negative event sequence (CWE-190)
	return d, true, nil
}

// DeploymentKEKDomain reads the deployment KEK state. found is false while the
// deployment KEK has never rotated (generation 0, the local key file).
func (s *Store) DeploymentKEKDomain(ctx context.Context) (DeploymentKEKDomain, bool, error) {
	return scanDeploymentKEKDomain(s.pool.QueryRow(ctx,
		`SELECT `+deploymentKEKColumns+` FROM public.deployment_kek_domain WHERE singleton`))
}

// DeploymentKEKDomainTx reads the deployment KEK state on an open transaction,
// typically a tenant's, so a seal uses the generation that transaction sees.
func (s *Store) DeploymentKEKDomainTx(ctx context.Context, tx pgx.Tx) (DeploymentKEKDomain, bool, error) {
	return scanDeploymentKEKDomain(tx.QueryRow(ctx,
		`SELECT `+deploymentKEKColumns+` FROM public.deployment_kek_domain WHERE singleton`))
}

// LockDeploymentKEKTx serializes deployment KEK transitions across replicas
// for the rest of the transaction.
func (s *Store) LockDeploymentKEKTx(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, deploymentKEKLockKey); err != nil {
		return fmt.Errorf("store: acquire the deployment KEK lock: %w", err)
	}
	return nil
}

// WithTenantKeyDomainSharedDeployment is WithTenantKeyDomainShared that also
// reads the deployment KEK state inside the same fenced transaction. A
// deployment KEK rotation records its next generation before it re-wraps any
// tenant's data under that tenant's exclusive fence, so a seal inside this
// callback either sees the next generation or finishes before the re-wrap of
// its tenant starts. deployment is nil while the deployment KEK has never
// rotated; both pointers are callback-scoped.
func (s *Store) WithTenantKeyDomainSharedDeployment(
	ctx context.Context,
	tenantID string,
	fn func(domain *TenantKeyDomain, deployment *DeploymentKEKDomain) error,
) error {
	if tenantID == "" {
		return fmt.Errorf("store: tenant key-domain access requires a tenant id (AN-1)")
	}
	if fn == nil {
		return errors.New("store: tenant key-domain access callback is required")
	}
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := s.LockTenantKeyDomainSharedTx(ctx, tx, tenantID); err != nil {
			return err
		}
		var deployment *DeploymentKEKDomain
		if d, found, err := s.DeploymentKEKDomainTx(ctx, tx); err != nil {
			return fmt.Errorf("store: read the deployment KEK under the tenant fence: %w", err)
		} else if found {
			deployment = &d
		}
		domain, err := s.GetTenantKeyDomainTx(ctx, tx, tenantID)
		if errors.Is(err, ErrTenantKeyDomainNotFound) {
			return fn(nil, deployment)
		}
		if err != nil {
			return fmt.Errorf("store: read tenant key domain under shared fence: %w", err)
		}
		return fn(&domain, deployment)
	})
}

// TenantsWithMigratedKeyDomainHistory lists the tenants whose key-domain
// migration completed, so their event history holds no deployment-KEK
// container any more. A deployment KEK rotation re-wraps every other tenant's
// history.
func (s *Store) TenantsWithMigratedKeyDomainHistory(ctx context.Context) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — a deployment KEK rotation must know, before it enters any tenant's scope, which tenants' history already left the deployment KEK; it reads tenant ids and a completion time only, never a key or payload. Cross-tenant by design; runs on the pool, not under RLS (AN-1 exemption).
		`SELECT tenant_id::text FROM tenant_key_domains WHERE migration_completed_at IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		out[tenantID] = true
	}
	return out, rows.Err()
}
