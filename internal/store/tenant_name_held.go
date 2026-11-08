// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ErrTenantNameHeld means another of the tenant's objects of that kind holds
// the name (LS-1). A refusal is a *TenantNameHeldError, which matches it.
var ErrTenantNameHeld = errors.New("store: another object of the tenant holds the name")

// TenantNameHeldError is a refused name: another of the tenant's objects of
// Kind holds Name.
type TenantNameHeldError struct{ Kind, Name string }

func (e *TenantNameHeldError) Error() string {
	return fmt.Sprintf("another %s is named %q; give this one a name of its own", e.Kind, e.Name)
}

// Is matches ErrTenantNameHeld.
func (e *TenantNameHeldError) Is(target error) bool { return target == ErrTenantNameHeld }

// tenantNameKinds names each checked read model's objects in a refusal.
var tenantNameKinds = map[string]string{
	"audit_feed_destinations":     "audit feed",
	"compliance_report_schedules": "report schedule",
}

// tenantNameHeldSQL is, for each read model with a tenant-unique name index
// its projection does not conflict on, the query whether another row holds a
// name (LS-1). Its projection used to meet the index only after the
// command's event was appended to the log, so a duplicate name left an event
// no rebuild could apply; the commands check first, and the projections
// apply such an event already in a log as the no-op it was live.
var tenantNameHeldSQL = map[string]string{
	"audit_feed_destinations":     `SELECT EXISTS (SELECT 1 FROM audit_feed_destinations WHERE tenant_id = $1 AND name = $2 AND id <> $3::uuid)`,
	"compliance_report_schedules": `SELECT EXISTS (SELECT 1 FROM compliance_report_schedules WHERE tenant_id = $1 AND name = $2 AND id <> $3::uuid)`,
}

// tenantNameHeldTx reports whether a row of table other than id holds name.
func tenantNameHeldTx(ctx context.Context, tx pgx.Tx, table, tenantID, id, name string) (bool, error) {
	query, ok := tenantNameHeldSQL[table]
	if !ok {
		return false, fmt.Errorf("store: %s has no tenant name check", table)
	}
	var held bool
	err := tx.QueryRow(ctx, query, tenantID, name, id).Scan(&held)
	return held, err
}

// EnsureTenantNameAvailable refuses a command that would give id a name
// another of the tenant's rows of table holds, with ErrTenantNameHeld; an
// object keeps its own name. Callers hold the projection lock across this
// check, the append and its projection.
func (s *Store) EnsureTenantNameAvailable(ctx context.Context, table, tenantID, id, name string) error {
	held := false
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		held, err = tenantNameHeldTx(ctx, tx, table, tenantID, id, name)
		return err
	}); err != nil {
		return err
	}
	if held {
		return &TenantNameHeldError{Kind: tenantNameKinds[table], Name: name}
	}
	return nil
}
