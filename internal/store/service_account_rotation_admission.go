// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/servicedependents"
)

// Caller holds the tenant PAM catalogue fence through command admission. This
// prevents an ordinary reset from racing a newly selected dependent host.
func (s *Store) SelectedServiceDependentAccount(ctx context.Context, tenantID, provider, dn string) (servicedependents.AccountBinding, bool, error) {
	var selected servicedependents.AccountBinding
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT DISTINCT binding->'account' FROM service_account_hosts WHERE tenant_id=$1 AND enabled AND binding->'account'->>'provider_id'=$2`, tenantID, provider)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				return e
			}
			var account servicedependents.AccountBinding
			if e = json.Unmarshal(raw, &account); e != nil {
				return e
			}
			if e = account.Validate(); e != nil {
				return e
			}
			if account.MatchesNative(provider, dn) {
				selected = account
				found = true
				return nil
			}
		}
		return rows.Err()
	})
	return selected, found, err
}

// The same tenant catalogue fence serializes host membership edits against
// ordinary and coordinated native commands. Terminal evidence remains readable.
func (s *Store) NativeStaticRotationInFlight(ctx context.Context, tenantID string, account servicedependents.AccountBinding) (bool, error) {
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT old_ref FROM secret_static_rotation_commands WHERE tenant_id=$1 AND provider=$2 AND terminal_at IS NULL`, tenantID, account.ProviderID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var dn string
			if e = rows.Scan(&dn); e != nil {
				return e
			}
			if account.MatchesNative(account.ProviderID, dn) {
				found = true
				return nil
			}
		}
		return rows.Err()
	})
	return found, err
}
