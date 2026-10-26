// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// A125/A196: each tenant's transit keyring is one sealed row every replica
// reads and writes. The store never sees key bytes: sealed is the container the
// transit service sealed under the tenant's key domain.

// LoadTransitKeyring returns the tenant's sealed transit keyring and its
// revision; found is false when the tenant has none.
func (s *Store) LoadTransitKeyring(ctx context.Context, tenantID string) ([]byte, int64, bool, error) {
	var (
		sealed   []byte
		revision int64
		found    bool
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT sealed, revision FROM transit_keyrings WHERE tenant_id = $1`, tenantID).
			Scan(&sealed, &revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return nil, 0, false, err
	}
	return sealed, revision, found, nil
}

// SaveTransitKeyring stores sealed as the tenant's keyring only if the stored
// revision is still expected (0: the tenant has no row) and returns the new
// revision. saved is false when another replica saved first; the caller
// reloads and applies its change again.
func (s *Store) SaveTransitKeyring(ctx context.Context, tenantID string, sealed []byte, expected int64) (int64, bool, error) {
	if tenantID == "" || len(sealed) == 0 || expected < 0 {
		return 0, false, errors.New("store: a transit keyring save needs a tenant, a sealed keyring and a revision")
	}
	var revision int64
	saved := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		if expected == 0 {
			err = tx.QueryRow(ctx, `INSERT INTO transit_keyrings (tenant_id, sealed, revision) VALUES ($1, $2, 1)
				ON CONFLICT (tenant_id) DO NOTHING RETURNING revision`, tenantID, sealed).Scan(&revision)
		} else {
			err = tx.QueryRow(ctx, `UPDATE transit_keyrings SET sealed = $2, revision = revision + 1, updated_at = now()
				WHERE tenant_id = $1 AND revision = $3 RETURNING revision`, tenantID, sealed, expected).Scan(&revision)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		saved = true
		return nil
	})
	if err != nil {
		return 0, false, err
	}
	return revision, saved, nil
}
