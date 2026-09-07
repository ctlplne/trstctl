// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var dynamicSecretEventNamespace = uuid.MustParse("908f1994-a04c-506c-8471-71897e290a4a")

// DynamicSecretEventID is the permanent producer identity for a dynamic-secret
// transition. The registration epoch is part of the name, so re-registering the
// same tenant UUID can safely reuse a public lease/operation id without finding
// retained evidence owned by the erased registration.
func DynamicSecretEventID(tenantID, tenantEpoch, purpose, commandID string) string {
	if tenantID == "" || tenantEpoch == "" || purpose == "" || commandID == "" {
		return ""
	}
	return "dynsecret-event-" + uuid.NewSHA1(dynamicSecretEventNamespace,
		[]byte(tenantID+"\x00"+tenantEpoch+"\x00"+purpose+"\x00"+commandID)).String()
}

// ErrDynamicSecretTenantEpochMismatch means a retained dynamic-secret command
// belongs to another registration of the same tenant UUID. The event remains in
// immutable history, but it has no authority over the current tenant lifecycle.
var ErrDynamicSecretTenantEpochMismatch = errors.New("store: dynamic-secret tenant lifecycle epoch differs")

// DynamicSecretTenantEpoch returns the registration epoch used by dynamic lease,
// operation, event, and outbox identities. It deliberately shares the durable
// application_secret_tenant_epochs row: offboarding rotates one secret-bearing
// command namespace, and backup restores one authority.
//
// Locking the tenants row before creating/loading the epoch serializes this path
// with OffboardTenant's final tenant deletion. ELI5: either this command belongs
// to the still-live tenant, or the eraser wins; it cannot appear halfway through
// an offboard and survive under a deleted registration.
func (s *Store) DynamicSecretTenantEpoch(ctx context.Context, tenantID string) (string, error) {
	if tenantID == "" {
		return "", ErrDynamicSecretTenantEpochMismatch
	}
	var epoch string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var resolveErr error
		epoch, resolveErr = ensureDynamicSecretTenantEpochTx(ctx, tx, tenantID)
		return resolveErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrDynamicSecretTenantEpochMismatch
	}
	if err != nil {
		return "", err
	}
	if epoch == "" {
		return "", ErrDynamicSecretTenantEpochMismatch
	}
	return epoch, nil
}

// ValidateDynamicSecretTenantEpochTx proves that the caller's explicit epoch is
// the current registered tenant lifecycle while holding both lifecycle rows.
func (s *Store) ValidateDynamicSecretTenantEpochTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, tenantEpoch string,
) error {
	if tenantID == "" || tenantEpoch == "" {
		return ErrDynamicSecretTenantEpochMismatch
	}
	if err := lockDynamicSecretTenantRegistrationTx(ctx, tx, tenantID); err != nil {
		return err
	}
	var current string
	err := tx.QueryRow(ctx, `
		SELECT epoch_id::text
		  FROM application_secret_tenant_epochs
		 WHERE tenant_id = $1
		 FOR KEY SHARE`, tenantID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDynamicSecretTenantEpochMismatch
	}
	if err != nil {
		return err
	}
	if current != tenantEpoch {
		return ErrDynamicSecretTenantEpochMismatch
	}
	return nil
}

// ResolveDynamicSecretTenantEpochTx validates a v2 explicit epoch, or maps a v1
// event to the current registration when its sequence is not older than that
// registration. The retained-history lifecycle classifier supplies the stronger
// queued-lease ownership proof for late v1 terminal events; sequence alone is not
// treated as sufficient terminal authority.
func (s *Store) ResolveDynamicSecretTenantEpochTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, eventEpoch string,
	eventSequence int64,
) (string, error) {
	if tenantID == "" || eventSequence <= 0 {
		return "", ErrDynamicSecretTenantEpochMismatch
	}
	if err := lockDynamicSecretTenantRegistrationTx(ctx, tx, tenantID); err != nil {
		return "", err
	}
	var registrationSequence int64
	var currentEpoch string
	err := tx.QueryRow(ctx, `
		SELECT tenant.event_seq, epoch.epoch_id::text
		  FROM tenants AS tenant
		  JOIN application_secret_tenant_epochs AS epoch
		    ON epoch.tenant_id = tenant.tenant_id
		 WHERE tenant.tenant_id = $1
		 FOR KEY SHARE OF tenant, epoch`, tenantID).Scan(&registrationSequence, &currentEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrDynamicSecretTenantEpochMismatch
	}
	if err != nil {
		return "", err
	}
	if currentEpoch == "" || eventSequence < registrationSequence ||
		(eventEpoch != "" && eventEpoch != currentEpoch) {
		return "", ErrDynamicSecretTenantEpochMismatch
	}
	return currentEpoch, nil
}

// ResolveDynamicSecretPendingTenantEpochTx is the one legacy mapping allowed to
// create registration authority. A v1 pending event is the lifecycle root, so a
// freshly registered tenant may not have an epoch row yet. The tenant row is
// locked and its exact registration sequence is checked before creation. Every
// result/terminal path continues using ResolveDynamicSecretTenantEpochTx and can
// therefore never synthesize authority from a late retained outcome.
func (s *Store) ResolveDynamicSecretPendingTenantEpochTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, eventEpoch string,
	eventSequence int64,
) (string, error) {
	if eventEpoch != "" {
		return s.ResolveDynamicSecretTenantEpochTx(
			ctx, tx, tenantID, eventEpoch, eventSequence)
	}
	if tenantID == "" || eventSequence <= 0 {
		return "", ErrDynamicSecretTenantEpochMismatch
	}
	var registrationSequence int64
	if err := tx.QueryRow(ctx, `
		SELECT event_seq
		  FROM tenants
		 WHERE tenant_id = $1
		 FOR KEY SHARE`, tenantID).Scan(&registrationSequence); errors.Is(err, pgx.ErrNoRows) {
		return "", ErrDynamicSecretTenantEpochMismatch
	} else if err != nil {
		return "", fmt.Errorf("store: lock dynamic-secret pending tenant registration: %w", err)
	}
	if eventSequence < registrationSequence {
		return "", ErrDynamicSecretTenantEpochMismatch
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO application_secret_tenant_epochs (tenant_id, epoch_id)
		VALUES ($1, gen_random_uuid())
		ON CONFLICT DO NOTHING`, tenantID); err != nil {
		return "", fmt.Errorf("store: create dynamic-secret pending tenant epoch: %w", err)
	}
	var currentEpoch string
	if err := tx.QueryRow(ctx, `
		SELECT epoch_id::text
		  FROM application_secret_tenant_epochs
		 WHERE tenant_id = $1
		 FOR KEY SHARE`, tenantID).Scan(&currentEpoch); err != nil {
		return "", err
	}
	if currentEpoch == "" {
		return "", ErrDynamicSecretTenantEpochMismatch
	}
	return currentEpoch, nil
}

func lockDynamicSecretTenantRegistrationTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	var present bool
	err := tx.QueryRow(ctx, `
		SELECT true
		  FROM tenants
		 WHERE tenant_id = $1
		 FOR KEY SHARE`, tenantID).Scan(&present)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDynamicSecretTenantEpochMismatch
	}
	if err != nil {
		return fmt.Errorf("store: lock dynamic-secret tenant registration: %w", err)
	}
	if !present {
		return ErrDynamicSecretTenantEpochMismatch
	}
	return nil
}

// The epoch inserts here and in ResolveDynamicSecretPendingTenantEpochTx use a
// target-less ON CONFLICT DO NOTHING on purpose: the table is unique on both
// tenant_id and epoch_id, and only a target-less clause absorbs a concurrent
// duplicate on either index (DP2-043/DP2-046 family). A per-tenant advisory lock
// was rejected because these run inside flows that already hold the per-command
// dynamic-secret lock in the other order. The FOR KEY SHARE read below then
// returns whichever epoch committed.
func ensureDynamicSecretTenantEpochTx(ctx context.Context, tx pgx.Tx, tenantID string) (string, error) {
	if err := lockDynamicSecretTenantRegistrationTx(ctx, tx, tenantID); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO application_secret_tenant_epochs (tenant_id, epoch_id)
		VALUES ($1, gen_random_uuid())
		ON CONFLICT DO NOTHING`, tenantID); err != nil {
		return "", fmt.Errorf("store: create dynamic-secret tenant epoch: %w", err)
	}
	var epoch string
	if err := tx.QueryRow(ctx, `
		SELECT epoch_id::text
		  FROM application_secret_tenant_epochs
		 WHERE tenant_id = $1
		 FOR KEY SHARE`, tenantID).Scan(&epoch); err != nil {
		return "", err
	}
	if epoch == "" {
		return "", ErrDynamicSecretTenantEpochMismatch
	}
	return epoch, nil
}

func (s *Store) resolveDynamicSecretWriteEpochTx(ctx context.Context, tx pgx.Tx, tenantID, tenantEpoch string) (string, error) {
	if tenantEpoch == "" {
		// Version-1 projector and direct-store compatibility. New producers always
		// carry an explicit epoch and therefore take the validation path below.
		return ensureDynamicSecretTenantEpochTx(ctx, tx, tenantID)
	}
	if err := s.ValidateDynamicSecretTenantEpochTx(ctx, tx, tenantID, tenantEpoch); err != nil {
		return "", err
	}
	return tenantEpoch, nil
}
