// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ListDeletedSecretsUnder returns the deleted secrets kept under prefix (a
// folder restore's "<project>/<environment>/[folder/]"), not under any of
// hidden, ordered by name and at most limit, without values (A236-L5).
func (s *Store) ListDeletedSecretsUnder(ctx context.Context, tenantID, prefix string, hidden []string, limit int) ([]DeletedSecret, error) {
	if hidden == nil {
		hidden = []string{}
	}
	var out []DeletedSecret
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT t.name, coalesce(t.owner_id::text, ''), t.version,
			        (SELECT count(*) FROM secret_store_tombstone_versions v
			          WHERE v.tenant_id = t.tenant_id AND v.name = t.name)::int,
			        t.created_at, t.deleted_at
			   FROM secret_store_tombstones t
			  WHERE t.tenant_id = $1 AND starts_with(t.name, $2)
			    AND NOT EXISTS (SELECT 1 FROM unnest($3::text[]) AS h(prefix) WHERE starts_with(t.name, h.prefix))
			  ORDER BY t.name
			  LIMIT $4`, tenantID, prefix, hidden, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d DeletedSecret
			if err := rows.Scan(&d.Name, &d.OwnerID, &d.Version, &d.Versions, &d.CreatedAt, &d.DeletedAt); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// GetDeletedSecretVersionAt returns the version of a deleted secret that was
// current at `at`, from its tombstone's history (A236-L5). It returns
// ErrSecretNotFound when the secret had no version then.
func (s *Store) GetDeletedSecretVersionAt(ctx context.Context, tenantID, name string, at time.Time) (SecretVersion, error) {
	var out SecretVersion
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var recovered sql.NullInt64
		if err := tx.QueryRow(ctx,
			`SELECT tenant_id::text, name, version, sealed, written_at, recovered_from_version
			   FROM secret_store_tombstone_versions
			  WHERE tenant_id = $1 AND name = $2 AND written_at <= $3
			  ORDER BY written_at DESC, version DESC
			  LIMIT 1`, tenantID, name, at.UTC()).
			Scan(&out.TenantID, &out.Name, &out.Version, &out.Sealed, &out.WrittenAt, &recovered); err != nil {
			return err
		}
		if recovered.Valid {
			v := int(recovered.Int64)
			out.RecoveredFromVersion = &v
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SecretVersion{}, ErrSecretNotFound
	}
	return out, err
}

// restoreApplicationSecretTombstoneTx brings a deleted secret back inside a
// versioned batch (A236-L5): its tombstone, which must be exactly the one the
// plan named, returns its owner, creation time and history to the live store,
// and the batch then writes the restored value as the next version. The
// caller holds the name's batch lock; a moved tombstone or a live secret under
// the name makes the batch stale.
func restoreApplicationSecretTombstoneTx(
	ctx context.Context, tx pgx.Tx, tenantID string, item ApplicationSecretVersionItem, at time.Time,
) (ApplicationSecretImportItem, error) {
	var rec ApplicationSecretImportItem
	// The batch holds the name's lock already; taking it here again (it is
	// re-entrant within the transaction) keeps the secret_store insert below
	// visibly serialized on its arbiter (OPP-C01).
	if err := lockApplicationSecretImportNameTx(ctx, tx, tenantID, item.Name); err != nil {
		return rec, err
	}
	var ownerID string
	var version int
	var createdAt, deletedAt time.Time
	err := tx.QueryRow(ctx,
		`SELECT coalesce(owner_id::text, ''), version, created_at, deleted_at
		   FROM secret_store_tombstones
		  WHERE tenant_id = $1 AND name = $2
		  FOR UPDATE`, tenantID, item.Name).Scan(&ownerID, &version, &createdAt, &deletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return rec, errApplicationSecretBatchStale(item.Name)
	}
	if err != nil {
		return rec, err
	}
	if version != item.Tombstone.Version || !deletedAt.Equal(item.Tombstone.DeletedAt) ||
		item.ResultVersion != version+1 {
		return rec, errApplicationSecretBatchStale(item.Name)
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO secret_store (tenant_id, name, sealed, version, created_at, updated_at, owner_id)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, '')::uuid)
		ON CONFLICT (tenant_id, name) DO NOTHING
		RETURNING name, version, created_at, updated_at`,
		tenantID, item.Name, item.Sealed, item.ResultVersion, createdAt.UTC(), at, ownerID).
		Scan(&rec.Name, &rec.Version, &rec.CreatedAt, &rec.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return rec, errApplicationSecretBatchStale(item.Name)
	}
	if err != nil {
		return rec, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO secret_store_versions (tenant_id, name, version, sealed, written_at, recovered_from_version)
		 SELECT tenant_id, name, version, sealed, written_at, recovered_from_version
		   FROM secret_store_tombstone_versions
		  WHERE tenant_id = $1 AND name = $2`, tenantID, item.Name); err != nil {
		return rec, err
	}
	_, err = tx.Exec(ctx, `DELETE FROM secret_store_tombstones WHERE tenant_id = $1 AND name = $2`, tenantID, item.Name)
	return rec, err
}

func errApplicationSecretBatchStale(name string) error {
	return fmt.Errorf("%w: %s", ErrApplicationSecretBatchStale, name)
}
