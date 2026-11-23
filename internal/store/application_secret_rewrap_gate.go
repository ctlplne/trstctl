// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrApplicationSecretRewrapPendingCommand = errors.New("store: settle pending application-secret commands before rewrap")
var ErrApplicationSecretRewrapLegacyReceipt = errors.New("store: authenticate and backfill v1 application-secret receipts before rewrap")
var ErrApplicationSecretRewrapInProgress = errors.New("store: application-secret rewrap is already in progress")

// IsApplicationSecretRewrapBusy recognizes both the coordinator's refusal and
// the SQL trigger protecting old writers that cannot see the Go-side gate.
func IsApplicationSecretRewrapBusy(err error) bool {
	return errors.Is(err, ErrApplicationSecretRewrapInProgress) || SQLState(err) == "TR001"
}

type ApplicationSecretRewrapGate struct {
	TenantEpoch string
	OperationID string
	Kind        string
	InProgress  bool
	V2Required  bool
	Generation  int64
}

type rewrapCoordinatorEventContextKey struct{}
type rewrapCoordinatorEventGrant struct {
	store       *Store
	tx          pgx.Tx
	tenantID    string
	operationID string
	eventType   string
	active      atomic.Bool
}

// WithRewrapCoordinatorEvent permits one exact operation's key-state snapshot
// event to use the already bound exclusive A/B transaction. The normal append
// path must not reacquire B behind this transaction's tenant and domain locks.
func (s *Store) WithRewrapCoordinatorEvent(ctx context.Context, tx pgx.Tx,
	tenantID, operationID, eventType string, fn func(context.Context) error,
) error {
	if s == nil || tx == nil || fn == nil || eventType == "" {
		return ErrApplicationSecretRewrapInProgress
	}
	if _, err := uuid.Parse(operationID); err != nil {
		return ErrApplicationSecretRewrapInProgress
	}
	if err := s.RequireKeyStateOwnerTx(ctx, tx, tenantID, KeyStateExclusive); err != nil {
		return err
	}
	gate, found, err := s.GetTenantApplicationSecretRewrapGateTx(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if !found || !gate.InProgress || gate.OperationID != operationID {
		return ErrApplicationSecretRewrapInProgress
	}
	grant := &rewrapCoordinatorEventGrant{store: s, tx: tx, tenantID: tenantID,
		operationID: operationID, eventType: eventType}
	grant.active.Store(true)
	defer grant.active.Store(false)
	return fn(context.WithValue(ctx, rewrapCoordinatorEventContextKey{}, grant))
}

// WithKeyStateSnapshotEvent lends the already-held exclusive key-state
// transaction to one seal/unseal snapshot or tenant offboard Append while no
// rewrap gate is armed.
// The event ingress must not reacquire B behind this transaction's row locks.
func (s *Store) WithKeyStateSnapshotEvent(ctx context.Context, tx pgx.Tx,
	tenantID, eventType string, fn func(context.Context) error,
) error {
	if s == nil || tx == nil || fn == nil || !isUnarmedKeyStateSnapshotEvent(eventType) {
		return ErrApplicationSecretRewrapInProgress
	}
	if err := s.RequireKeyStateOwnerTx(ctx, tx, tenantID, KeyStateExclusive); err != nil {
		return err
	}
	gate, found, err := s.GetTenantApplicationSecretRewrapGateTx(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if found && gate.InProgress {
		return ErrApplicationSecretRewrapInProgress
	}
	grant := &rewrapCoordinatorEventGrant{store: s, tx: tx, tenantID: tenantID, eventType: eventType}
	grant.active.Store(true)
	defer grant.active.Store(false)
	return fn(context.WithValue(ctx, rewrapCoordinatorEventContextKey{}, grant))
}

func isUnarmedKeyStateSnapshotEvent(eventType string) bool {
	switch eventType {
	case "tenant.key_domain.seal_requested", "tenant.key_domain.seal_failed",
		"tenant.key_domain.sealed", "tenant.key_domain.unseal_requested",
		"tenant.key_domain.unsealed", "tenant.offboarded":
		return true
	}
	return false
}

func (s *Store) requireKeyStateSnapshotEvent(ctx context.Context, tenantID, eventType string) error {
	grant, ok := ctx.Value(rewrapCoordinatorEventContextKey{}).(*rewrapCoordinatorEventGrant)
	if !ok || grant == nil || !grant.active.Load() || grant.store != s ||
		grant.tenantID != tenantID || grant.eventType != eventType {
		return ErrApplicationSecretRewrapInProgress
	}
	if err := s.RequireKeyStateOwnerTx(ctx, grant.tx, tenantID, KeyStateExclusive); err != nil {
		return err
	}
	gate, found, err := s.GetTenantApplicationSecretRewrapGateTx(ctx, grant.tx, tenantID)
	if err != nil {
		return err
	}
	if grant.operationID == "" {
		if found && gate.InProgress || !isUnarmedKeyStateSnapshotEvent(eventType) {
			return ErrApplicationSecretRewrapInProgress
		}
	} else if !found || !gate.InProgress || gate.OperationID != grant.operationID {
		return ErrApplicationSecretRewrapInProgress
	}
	return nil
}

// HasKeyStateSnapshotEvent reports only a currently active in-process grant;
// the caller must still use RequireRewrapCoordinatorEventTx to prove its SQL
// owner and gate binding before accepting the event.
func (s *Store) HasKeyStateSnapshotEvent(ctx context.Context) bool {
	grant, ok := ctx.Value(rewrapCoordinatorEventContextKey{}).(*rewrapCoordinatorEventGrant)
	return ok && grant != nil && grant.store == s && grant.active.Load()
}

func (s *Store) RequireRewrapCoordinatorEventTx(ctx context.Context, tx pgx.Tx, tenantID, eventType string) error {
	grant, ok := ctx.Value(rewrapCoordinatorEventContextKey{}).(*rewrapCoordinatorEventGrant)
	if !ok || grant == nil || grant.tx != tx || grant.operationID == "" {
		return ErrApplicationSecretRewrapInProgress
	}
	return s.requireKeyStateSnapshotEvent(ctx, tenantID, eventType)
}

// GetTenantApplicationSecretRewrapGate reads the durable admission state in
// the tenant's RLS context. Absence is distinct from an unarmed completed gate.
func (s *Store) GetTenantApplicationSecretRewrapGate(ctx context.Context, tenantID string) (ApplicationSecretRewrapGate, bool, error) {
	var gate ApplicationSecretRewrapGate
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var inner error
		gate, found, inner = s.GetTenantApplicationSecretRewrapGateTx(ctx, tx, tenantID)
		return inner
	})
	return gate, found, err
}

// GetTenantApplicationSecretRewrapGateTx reads the same tenant state from the
// caller's projection transaction. Its owner must hold the global key-state
// commit lock through commit before relying on this generation.
func (s *Store) GetTenantApplicationSecretRewrapGateTx(
	ctx context.Context, tx pgx.Tx, tenantID string,
) (ApplicationSecretRewrapGate, bool, error) {
	var gate ApplicationSecretRewrapGate
	if s == nil || tx == nil || tenantID == "" {
		return gate, false, ErrApplicationSecretRewrapInProgress
	}
	err := tx.QueryRow(ctx, `SELECT tenant_epoch::text,operation_id::text,operation_kind,
		rewrap_in_progress,v2_required,generation
		FROM application_secret_rewrap_gates WHERE tenant_id=$1`, tenantID).
		Scan(&gate.TenantEpoch, &gate.OperationID, &gate.Kind, &gate.InProgress, &gate.V2Required, &gate.Generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return gate, false, nil
	}
	return gate, err == nil, err
}

// BeginTenantApplicationSecretRewrap reserves one tenant's independent receipt
// and pending-command state before the first hot-state rewrite. The SQL trigger
// serializes this transition with writers from older and newer replicas. A
// retry of the same operation kind resumes the recorded operation ID.
func (s *Store) BeginTenantApplicationSecretRewrap(ctx context.Context, tenantID, kind string) (string, error) {
	var operationID string
	err := s.WithGlobalKeyStateAdmission(ctx, KeyStateExclusive, func(admitted context.Context) error {
		if err := s.requireRewrapFleetCutoverAdmitted(admitted, s.rewrapFleetCutover); err != nil {
			return err
		}
		var inner error
		operationID, inner = s.beginTenantApplicationSecretRewrapAdmitted(admitted, tenantID, kind)
		return inner
	})
	return operationID, err
}

func (s *Store) beginTenantApplicationSecretRewrapAdmitted(ctx context.Context, tenantID, kind string) (string, error) {
	if tenantID == "" || kind != "migrate" && kind != "rotate" && kind != "deployment" {
		return "", errors.New("store: tenant rewrap gate requires a tenant and known operation kind")
	}
	epoch, err := s.ApplicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return "", err
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.LockGlobalKeyStateCommitTx(ctx, tx, KeyStateExclusive); err != nil {
		return "", err
	}
	//trstctl:system-query — the cross-tenant system advisory namespace is keyed by tenant_id; this lock call reads no tenant row or payload.
	if _, err := tx.Exec(ctx, `SELECT application_secret_rewrap_gate_lock($1::uuid)`, tenantID); err != nil {
		return "", err
	}
	if err := s.requireNoUnresolvedRewrapActivityTx(ctx, tx, tenantID); err != nil {
		return "", err
	}
	var existingEpoch, operationID, existingKind string
	var inProgress bool
	err = tx.QueryRow(ctx, `SELECT tenant_epoch::text,operation_id::text,operation_kind,rewrap_in_progress
		FROM application_secret_rewrap_gates WHERE tenant_id=$1 FOR UPDATE`, tenantID).
		Scan(&existingEpoch, &operationID, &existingKind, &inProgress)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if err == nil && existingEpoch != epoch {
		return "", fmt.Errorf("%w: tenant lifecycle epoch changed", ErrApplicationSecretRewrapInProgress)
	}
	if inProgress && existingKind != kind {
		return "", ErrApplicationSecretRewrapInProgress
	}
	if inProgress {
		if err := tx.Commit(ctx); err != nil {
			return "", err
		}
		return operationID, nil
	}
	var pending, legacy bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM application_secret_mutation_fences WHERE tenant_id=$1),
		EXISTS(SELECT 1 FROM application_secret_mutation_receipts WHERE tenant_id=$1 AND semantic_sha256_v2 IS NULL)`, tenantID).
		Scan(&pending, &legacy); err != nil {
		return "", err
	}
	if pending {
		return "", ErrApplicationSecretRewrapPendingCommand
	}
	if legacy {
		return "", ErrApplicationSecretRewrapLegacyReceipt
	}
	operationID = uuid.NewString()
	if _, err := tx.Exec(ctx, `INSERT INTO application_secret_rewrap_gates
		(tenant_id,tenant_epoch,operation_id,operation_kind,rewrap_in_progress,v2_required)
		VALUES ($1,$2,$3,$4,true,true)
		ON CONFLICT (tenant_id) DO UPDATE SET
		  operation_id=EXCLUDED.operation_id,operation_kind=EXCLUDED.operation_kind,
		  rewrap_in_progress=true,v2_required=true`, tenantID, epoch, operationID, kind); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return operationID, nil
}

// BeginDeploymentApplicationSecretRewrap arms all known tenants in one owner
// transaction. A pending command or v1-only receipt in any tenant rolls back
// every gate, so a partial deployment gate is never published.
func (s *Store) BeginDeploymentApplicationSecretRewrap(ctx context.Context, operationID string, tenantIDs []string) error {
	return s.WithGlobalKeyStateAdmission(ctx, KeyStateExclusive, func(admitted context.Context) error {
		if err := s.requireRewrapFleetCutoverAdmitted(admitted, s.rewrapFleetCutover); err != nil {
			return err
		}
		return s.beginDeploymentApplicationSecretRewrapAdmitted(admitted, operationID, tenantIDs)
	})
}

func (s *Store) beginDeploymentApplicationSecretRewrapAdmitted(ctx context.Context, operationID string, tenantIDs []string) error {
	if _, err := uuid.Parse(operationID); err != nil {
		return errors.New("store: deployment rewrap requires an operation UUID")
	}
	if len(tenantIDs) == 0 {
		return errors.New("store: deployment rewrap requires a nonempty tenant inventory")
	}
	tenants := slices.Clone(tenantIDs)
	slices.Sort(tenants)
	for i, tenantID := range tenants {
		if _, err := uuid.Parse(tenantID); err != nil || i > 0 && tenantID == tenants[i-1] {
			return errors.New("store: deployment rewrap tenant inventory is invalid")
		}
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.LockGlobalKeyStateCommitTx(ctx, tx, KeyStateExclusive); err != nil {
		return err
	}
	//trstctl:system-query — the cross-tenant system deployment advisory lock reads no tenant row or payload and serializes one cutover.
	if _, err := tx.Exec(ctx, `SELECT application_secret_deployment_rewrap_lock()`); err != nil {
		return err
	}
	// Registration uses the same lock in its SQL trigger. A tenant that appeared
	// after the caller's inventory read must make this activation retry rather
	// than escape the deployment-wide wrapper change.
	//trstctl:system-query — cross-tenant system inventory reads tenant_id only so the owner-only deployment coordinator can reject an incomplete caller inventory; every later gate write uses an exact tenant predicate.
	rows, err := tx.Query(ctx, `SELECT tenant_id::text FROM tenants ORDER BY tenant_id`)
	if err != nil {
		return err
	}
	var live []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			rows.Close()
			return err
		}
		live = append(live, tenantID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if !slices.Equal(live, tenants) {
		return ErrApplicationSecretRewrapInProgress
	}
	for _, tenantID := range tenants {
		//trstctl:system-query — the cross-tenant system advisory namespace is keyed by tenant_id; this lock call reads no tenant row or payload.
		if _, err := tx.Exec(ctx, `SELECT application_secret_rewrap_gate_lock($1::uuid)`, tenantID); err != nil {
			return err
		}
		if err := s.requireNoUnresolvedRewrapActivityTx(ctx, tx, tenantID); err != nil {
			return err
		}
		var epoch string
		if err := tx.QueryRow(ctx, `SELECT epoch_id::text FROM application_secret_tenant_epochs WHERE tenant_id=$1`, tenantID).Scan(&epoch); err != nil {
			return err
		}
		var existingEpoch, existingOperation, existingKind string
		var inProgress bool
		err := tx.QueryRow(ctx, `SELECT tenant_epoch::text,operation_id::text,operation_kind,rewrap_in_progress
			FROM application_secret_rewrap_gates WHERE tenant_id=$1 FOR UPDATE`, tenantID).
			Scan(&existingEpoch, &existingOperation, &existingKind, &inProgress)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && existingEpoch != epoch || inProgress && (existingKind != "deployment" || existingOperation != operationID) {
			return ErrApplicationSecretRewrapInProgress
		}
		var pending, legacy bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM application_secret_mutation_fences WHERE tenant_id=$1),
			EXISTS(SELECT 1 FROM application_secret_mutation_receipts WHERE tenant_id=$1 AND semantic_sha256_v2 IS NULL)`, tenantID).
			Scan(&pending, &legacy); err != nil {
			return err
		}
		if pending {
			return ErrApplicationSecretRewrapPendingCommand
		}
		if legacy {
			return ErrApplicationSecretRewrapLegacyReceipt
		}
		if _, err := tx.Exec(ctx, `INSERT INTO application_secret_rewrap_gates
			(tenant_id,tenant_epoch,operation_id,operation_kind,rewrap_in_progress,v2_required)
			VALUES ($1,$2,$3,'deployment',true,true)
			ON CONFLICT (tenant_id) DO UPDATE SET
			  operation_id=EXCLUDED.operation_id,operation_kind='deployment',
			  rewrap_in_progress=true,v2_required=true`, tenantID, epoch, operationID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// A lost broker/database session can leave an event publish or projection
// outcome unknown. The coordinator must not rewrap history until that exact
// tenant's durable starts are independently reconciled.
func (s *Store) requireNoUnresolvedRewrapActivityTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if err := s.SetTenantGUCTx(ctx, tx, tenantID); err != nil {
		return err
	}
	// The exact live coordinator's own durable start brackets this gate
	// transition. It is still visible to full restore, but must not block
	// itself. Every other started token remains a hard rewrap refusal.
	excluded := uuid.Nil.String()
	if token, ok := ctx.Value(restoreActivityTokenContextKey{}).(*restoreActivityToken); ok &&
		token != nil && token.origin == s && token.lease != nil && token.lease.active.Load() &&
		token.active.Load() && token.tenantID == tenantID && token.kind == "maintenance" &&
		(token.lane == "tenant-domain-migrate" || token.lane == "tenant-domain-rotate") {
		excluded = token.operationID
	}
	var unresolved bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND phase='started' AND operation_id<>$2)`, tenantID, excluded).Scan(&unresolved); err != nil {
		return err
	}
	if unresolved {
		return ErrRestoreActivityUnresolved
	}
	// The activity token can be terminal while a broker ACK remains ambiguous.
	// The target-local producer journal carries that uncertainty independently
	// until exact canonical evidence settles it.
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trstctl_recovery.event_ingress_journal
		WHERE tenant_id=$1 AND phase IN ('started','candidate_staged'))`, tenantID).Scan(&unresolved); err != nil {
		return err
	}
	if unresolved {
		return ErrRestoreActivityUnresolved
	}
	return nil
}

// CompleteDeploymentApplicationSecretRewrap releases one verified deployment
// operation's tenant gates together. Repeated completion is safe after a crash
// between the deployment snapshot commit and this gate transaction.
func (s *Store) CompleteDeploymentApplicationSecretRewrap(ctx context.Context, operationID string) error {
	return s.WithGlobalKeyStateAdmission(ctx, KeyStateExclusive, func(admitted context.Context) error {
		if err := s.requireRewrapFleetCutoverAdmitted(admitted, s.rewrapFleetCutover); err != nil {
			return err
		}
		return s.completeDeploymentApplicationSecretRewrapAdmitted(admitted, operationID)
	})
}

func (s *Store) completeDeploymentApplicationSecretRewrapAdmitted(ctx context.Context, operationID string) error {
	if _, err := uuid.Parse(operationID); err != nil {
		return errors.New("store: deployment rewrap completion requires an operation UUID")
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.LockGlobalKeyStateCommitTx(ctx, tx, KeyStateExclusive); err != nil {
		return err
	}
	//trstctl:system-query — the cross-tenant system deployment advisory lock reads no tenant row or payload and serializes one cutover.
	if _, err := tx.Exec(ctx, `SELECT application_secret_deployment_rewrap_lock()`); err != nil {
		return err
	}
	//trstctl:system-query — cross-tenant by design: this owner-only system operation lists tenant_id only for the exact deployment rewrap operation, then updates every row by tenant_id and operation_id.
	rows, err := tx.Query(ctx, `SELECT tenant_id::text FROM application_secret_rewrap_gates
		WHERE operation_id=$1 AND operation_kind='deployment' ORDER BY tenant_id`, operationID)
	if err != nil {
		return err
	}
	var tenants []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			rows.Close()
			return err
		}
		tenants = append(tenants, tenantID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(tenants) == 0 {
		return ErrApplicationSecretRewrapInProgress
	}
	for _, tenantID := range tenants {
		//trstctl:system-query — the cross-tenant system advisory namespace is keyed by tenant_id; this lock call reads no tenant row or payload.
		if _, err := tx.Exec(ctx, `SELECT application_secret_rewrap_gate_lock($1::uuid)`, tenantID); err != nil {
			return err
		}
		if err := s.requireNoUnresolvedRewrapActivityTx(ctx, tx, tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE application_secret_rewrap_gates
			SET rewrap_in_progress=false
			WHERE tenant_id=$1 AND operation_id=$2 AND operation_kind='deployment'
			AND rewrap_in_progress=true`, tenantID, operationID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// CompleteTenantApplicationSecretRewrap releases the temporary write fence only
// for the exact coordinator operation. The SQL trigger retains v2-required and
// increments the lifecycle generation for later canonical replay checks.
func (s *Store) CompleteTenantApplicationSecretRewrap(ctx context.Context, tenantID, operationID string) error {
	return s.WithGlobalKeyStateAdmission(ctx, KeyStateExclusive, func(admitted context.Context) error {
		if err := s.requireRewrapFleetCutoverAdmitted(admitted, s.rewrapFleetCutover); err != nil {
			return err
		}
		return s.completeTenantApplicationSecretRewrapAdmitted(admitted, tenantID, operationID)
	})
}

func (s *Store) completeTenantApplicationSecretRewrapAdmitted(ctx context.Context, tenantID, operationID string) error {
	if tenantID == "" || operationID == "" {
		return errors.New("store: tenant rewrap completion requires tenant and operation")
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.LockGlobalKeyStateCommitTx(ctx, tx, KeyStateExclusive); err != nil {
		return err
	}
	//trstctl:system-query — the cross-tenant system advisory namespace is keyed by tenant_id; this lock call reads no tenant row or payload.
	if _, err := tx.Exec(ctx, `SELECT application_secret_rewrap_gate_lock($1::uuid)`, tenantID); err != nil {
		return err
	}
	if err := s.requireNoUnresolvedRewrapActivityTx(ctx, tx, tenantID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE application_secret_rewrap_gates SET rewrap_in_progress=false
		WHERE tenant_id=$1 AND operation_id=$2 AND rewrap_in_progress=true`, tenantID, operationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrApplicationSecretRewrapInProgress
	}
	return tx.Commit(ctx)
}
