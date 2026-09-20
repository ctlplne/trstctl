// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrTenantKeyDomainNotFound = errors.New("store: tenant key domain not found")

const (
	TenantKeyProtectionTenantDomain = "tenant_domain"

	TenantKeyDomainStateMigrating          = "migrating"
	TenantKeyDomainStatePartial            = "partial"
	TenantKeyDomainStateUnsealed           = "unsealed"
	TenantKeyDomainStateSealQueued         = "seal_queued"
	TenantKeyDomainStateSealing            = "sealing"
	TenantKeyDomainStateSealed             = "sealed"
	TenantKeyDomainStateUnsealing          = "unsealing"
	TenantKeyDomainStateWrapperUnavailable = "wrapper_unavailable"
	TenantKeyDomainStateWrongWrapper       = "wrong_wrapper"
	TenantKeyDomainStateCorrupt            = "corrupt"

	TenantKeyOperationMigrate = "migrate"
	TenantKeyOperationSeal    = "seal"
	TenantKeyOperationUnseal  = "unseal"

	TenantKeyOperationPending   = "pending"
	TenantKeyOperationRunning   = "running"
	TenantKeyOperationCompleted = "completed"
	TenantKeyOperationFailed    = "failed"

	TenantKeyLegacyNone                     = "none"
	TenantKeyLegacyHotHistoryPending        = "hot_history_pending"
	TenantKeyLegacyExternalArchivesPossible = "external_archives_possible"
)

// TenantKeyDomain is the event-derived current state of one tenant's
// independently wrapped cryptographic domain. WrappedDomainKEK remains binary
// end-to-end (AN-8); WrapperID is only a configuration reference, never key
// material. A missing row means legacy deployment-KEK protection and is
// synthesized by the service/API rather than persisted as a pretend domain.
type TenantKeyDomain struct {
	TenantID                   string
	DomainID                   string
	Generation                 int64
	ProtectionMode             string
	State                      string
	WrapperKind                string
	WrapperID                  string
	WrappedDomainKEK           []byte
	OperationID                *string
	OperationKind              string
	OperationStatus            string
	MigrationStage             string
	ProgressCompleted          int64
	ProgressTotal              int64
	ProgressCursor             string
	Retryable                  bool
	LastErrorCode              string
	LastError                  string
	LegacyHistoryExposure      string
	MigrationStartedAt         *time.Time
	MigrationCompletedAt       *time.Time
	SealedAt                   *time.Time
	UnsealedAt                 *time.Time
	LastTransitionEventID      string
	LastTransitionType         string
	LastTransitionActor        string
	LastTransitionAt           time.Time
	LastTransitionEvidenceRefs []string
	LastTransitionSequence     uint64
	CreatedAt                  time.Time
	UpdatedAt                  time.Time
}

// ApplyTenantKeyDomainSnapshotTx projects one full tenant.key_domain.* event
// snapshot. The event sequence is a monotonic guard: a lagging durable projector
// cannot overwrite a newer inline projection with an older lifecycle state.
func (s *Store) ApplyTenantKeyDomainSnapshotTx(ctx context.Context, tx pgx.Tx, domain TenantKeyDomain) error {
	evidenceRefs := domain.LastTransitionEvidenceRefs
	if evidenceRefs == nil {
		evidenceRefs = []string{}
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO tenant_key_domains
		        (tenant_id, domain_id, generation, protection_mode, state,
		         wrapper_kind, wrapper_id, wrapped_domain_kek,
		         operation_id, operation_kind, operation_status, migration_stage,
		         progress_completed, progress_total, progress_cursor, retryable,
		         last_error_code, last_error, legacy_history_exposure,
		         migration_started_at, migration_completed_at, sealed_at, unsealed_at,
		         last_transition_event_id, last_transition_type, last_transition_actor,
		         last_transition_at, last_transition_evidence_refs,
		         last_transition_sequence, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
		         $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25,
		         $26, $27, $28, $29, $30, $31)
		 ON CONFLICT (tenant_id) DO UPDATE SET
		     domain_id = EXCLUDED.domain_id,
		     generation = EXCLUDED.generation,
		     protection_mode = EXCLUDED.protection_mode,
		     state = EXCLUDED.state,
		     wrapper_kind = EXCLUDED.wrapper_kind,
		     wrapper_id = EXCLUDED.wrapper_id,
		     wrapped_domain_kek = EXCLUDED.wrapped_domain_kek,
		     operation_id = EXCLUDED.operation_id,
		     operation_kind = EXCLUDED.operation_kind,
		     operation_status = EXCLUDED.operation_status,
		     migration_stage = EXCLUDED.migration_stage,
		     progress_completed = EXCLUDED.progress_completed,
		     progress_total = EXCLUDED.progress_total,
		     progress_cursor = EXCLUDED.progress_cursor,
		     retryable = EXCLUDED.retryable,
		     last_error_code = EXCLUDED.last_error_code,
		     last_error = EXCLUDED.last_error,
		     legacy_history_exposure = EXCLUDED.legacy_history_exposure,
		     migration_started_at = EXCLUDED.migration_started_at,
		     migration_completed_at = EXCLUDED.migration_completed_at,
		     sealed_at = EXCLUDED.sealed_at,
		     unsealed_at = EXCLUDED.unsealed_at,
		     last_transition_event_id = EXCLUDED.last_transition_event_id,
		     last_transition_type = EXCLUDED.last_transition_type,
		     last_transition_actor = EXCLUDED.last_transition_actor,
		     last_transition_at = EXCLUDED.last_transition_at,
		     last_transition_evidence_refs = EXCLUDED.last_transition_evidence_refs,
		     last_transition_sequence = EXCLUDED.last_transition_sequence,
		     created_at = tenant_key_domains.created_at,
		     updated_at = EXCLUDED.updated_at
		 WHERE EXCLUDED.last_transition_sequence > tenant_key_domains.last_transition_sequence`,
		domain.TenantID, domain.DomainID, domain.Generation, domain.ProtectionMode,
		domain.State, domain.WrapperKind, domain.WrapperID, domain.WrappedDomainKEK,
		domain.OperationID, domain.OperationKind, domain.OperationStatus,
		domain.MigrationStage, domain.ProgressCompleted, domain.ProgressTotal,
		domain.ProgressCursor, domain.Retryable, domain.LastErrorCode, domain.LastError,
		domain.LegacyHistoryExposure, domain.MigrationStartedAt,
		domain.MigrationCompletedAt, domain.SealedAt, domain.UnsealedAt,
		domain.LastTransitionEventID, domain.LastTransitionType,
		domain.LastTransitionActor, domain.LastTransitionAt, evidenceRefs,
		int64(domain.LastTransitionSequence), domain.CreatedAt, domain.UpdatedAt) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
	return err
}

// GetTenantKeyDomain reads the caller tenant's independently wrapped domain. A
// missing row is returned as ErrTenantKeyDomainNotFound so the service can
// synthesize the explicit legacy_deployment_kek status.
func (s *Store) GetTenantKeyDomain(ctx context.Context, tenantID string) (TenantKeyDomain, error) {
	var out TenantKeyDomain
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = s.GetTenantKeyDomainTx(ctx, tx, tenantID)
		return err
	})
	return out, err
}

// WithTenantKeyDomainShared runs fn while holding this tenant's shared
// key-domain advisory fence inside the same RLS-scoped PostgreSQL transaction
// that reads the domain projection. A migration, seal, or unseal transition
// cannot acquire its matching exclusive fence until fn returns and this
// transaction releases the shared fence.
//
// A nil domain means the tenant has no key-domain row and therefore still uses
// legacy deployment-KEK protection. The domain pointer is callback-scoped.
func (s *Store) WithTenantKeyDomainShared(
	ctx context.Context,
	tenantID string,
	fn func(*TenantKeyDomain) error,
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
		domain, err := s.GetTenantKeyDomainTx(ctx, tx, tenantID)
		if errors.Is(err, ErrTenantKeyDomainNotFound) {
			return fn(nil)
		}
		if err != nil {
			return fmt.Errorf("store: read tenant key domain under shared fence: %w", err)
		}
		return fn(&domain)
	})
}

// GetTenantKeyDomainTx reads the domain on an existing tenant transaction. A
// lifecycle command takes the matching advisory lock first, then calls this
// method so validation and event append observe one fenced state.
func (s *Store) GetTenantKeyDomainTx(ctx context.Context, tx pgx.Tx, tenantID string) (TenantKeyDomain, error) {
	var out TenantKeyDomain
	var transitionSequence int64
	err := tx.QueryRow(ctx,
		`SELECT tenant_id::text, domain_id::text, generation, protection_mode, state,
		        wrapper_kind, wrapper_id, wrapped_domain_kek,
		        operation_id::text, operation_kind, operation_status, migration_stage,
		        progress_completed, progress_total, progress_cursor, retryable,
		        last_error_code, last_error, legacy_history_exposure,
		        migration_started_at, migration_completed_at, sealed_at, unsealed_at,
		        last_transition_event_id, last_transition_type, last_transition_actor,
		        last_transition_at, last_transition_evidence_refs,
		        last_transition_sequence, created_at, updated_at
		   FROM tenant_key_domains
		  WHERE tenant_id = $1`,
		tenantID).Scan(
		&out.TenantID, &out.DomainID, &out.Generation, &out.ProtectionMode,
		&out.State, &out.WrapperKind, &out.WrapperID, &out.WrappedDomainKEK,
		&out.OperationID, &out.OperationKind, &out.OperationStatus,
		&out.MigrationStage, &out.ProgressCompleted, &out.ProgressTotal,
		&out.ProgressCursor, &out.Retryable, &out.LastErrorCode, &out.LastError,
		&out.LegacyHistoryExposure, &out.MigrationStartedAt,
		&out.MigrationCompletedAt, &out.SealedAt, &out.UnsealedAt,
		&out.LastTransitionEventID, &out.LastTransitionType,
		&out.LastTransitionActor, &out.LastTransitionAt,
		&out.LastTransitionEvidenceRefs, &transitionSequence, &out.CreatedAt,
		&out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TenantKeyDomain{}, ErrTenantKeyDomainNotFound
	}
	if err != nil {
		return TenantKeyDomain{}, err
	}
	if transitionSequence < 0 {
		return TenantKeyDomain{}, fmt.Errorf("store: tenant key domain has negative transition sequence")
	}
	out.LastTransitionSequence = uint64(transitionSequence)
	return out, nil
}

const tenantKeyDomainLockNamespace = "tenant-key-domain\x1f"

// LockTenantKeyDomainSharedTx fences ordinary crypto work for one tenant. A seal
// transition waits for every shared holder on every replica to finish before it
// can commit the sealed state.
func (s *Store) LockTenantKeyDomainSharedTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	return lockTenantKeyDomainTx(ctx, tx, tenantID, true)
}

// LockTenantKeyDomainExclusiveTx fences migration/seal/unseal transitions for
// one tenant without pausing independent tenants.
func (s *Store) LockTenantKeyDomainExclusiveTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	return lockTenantKeyDomainTx(ctx, tx, tenantID, false)
}

func lockTenantKeyDomainTx(ctx context.Context, tx pgx.Tx, tenantID string, shared bool) error {
	if tenantID == "" {
		return fmt.Errorf("store: tenant key-domain lock requires a tenant id (AN-1)")
	}
	var scopedTenantID string
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(current_setting('trstctl.tenant_id', true), '')`).Scan(&scopedTenantID); err != nil {
		return fmt.Errorf("store: read tenant key-domain lock scope: %w", err)
	}
	if scopedTenantID != tenantID {
		return fmt.Errorf("store: tenant key-domain lock tenant does not match transaction scope (AN-1)")
	}
	query := `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`
	mode := "exclusive"
	if shared {
		query = `SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))`
		mode = "shared"
	}
	if _, err := tx.Exec(ctx, query, tenantKeyDomainLockNamespace+tenantID); err != nil {
		return fmt.Errorf("store: acquire tenant key-domain %s lock: %w", mode, err)
	}
	return nil
}
