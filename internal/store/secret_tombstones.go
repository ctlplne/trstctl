// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ApplicationSecretTombstoneRef names one exact kept deletion: the version
// the secret had when it was deleted and the deletion time. A restore names it
// (A236-L4), and the fence or batch reservation that carries the restore
// checks it under the name's lock before anything is recorded.
type ApplicationSecretTombstoneRef struct {
	Version   int
	DeletedAt time.Time
}

// DeletedSecret is a deleted application secret kept as a tombstone (A236-L4):
// metadata only, never the sealed value. Version is the version the secret had
// when it was deleted, the one a restore brings back.
type DeletedSecret struct {
	Name      string
	OwnerID   string
	Version   int
	Versions  int
	CreatedAt time.Time
	DeletedAt time.Time
}

// ListDeletedSecrets returns the tenant's deleted secrets still kept as
// tombstones, most recently deleted first, without values. hidden holds name
// prefixes the caller may not read (a restricted environment it is not granted,
// A235); they are left out as they are from the live list. Tenant-scoped under
// RLS (AN-1).
func (s *Store) ListDeletedSecrets(ctx context.Context, tenantID string, hidden []string, limit int) ([]DeletedSecret, error) {
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
			  WHERE t.tenant_id = $1
			    AND NOT EXISTS (SELECT 1 FROM unnest($2::text[]) AS h(prefix) WHERE starts_with(t.name, h.prefix))
			  ORDER BY t.deleted_at DESC, t.name
			  LIMIT $3`, tenantID, hidden, limit)
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

// GetDeletedSecret returns one tombstone and the sealed value a restore brings
// back (the version the secret had when deleted). It returns ErrSecretNotFound
// when no tombstone is kept for the name. The restore command binds the
// version, the deletion time and these sealed bytes; the apply rechecks them
// under the lock.
func (s *Store) GetDeletedSecret(ctx context.Context, tenantID, name string) (DeletedSecret, []byte, error) {
	var d DeletedSecret
	var sealed []byte
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT t.name, coalesce(t.owner_id::text, ''), t.version,
			        (SELECT count(*) FROM secret_store_tombstone_versions v
			          WHERE v.tenant_id = t.tenant_id AND v.name = t.name)::int,
			        t.created_at, t.deleted_at
			   FROM secret_store_tombstones t
			  WHERE t.tenant_id = $1 AND t.name = $2`, tenantID, name).
			Scan(&d.Name, &d.OwnerID, &d.Version, &d.Versions, &d.CreatedAt, &d.DeletedAt); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT sealed FROM secret_store_tombstone_versions
			  WHERE tenant_id = $1 AND name = $2 AND version = $3`, tenantID, name, d.Version).Scan(&sealed)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DeletedSecret{}, nil, ErrSecretNotFound
	}
	return d, sealed, err
}

// PurgeDeletedSecret removes one tombstone and its sealed history now, before
// the retention window ends (A236-L4). It reports whether one was kept. It
// takes the lock every command on the name takes and refuses
// (ErrApplicationSecretMutationInFlight) while a command or a batch holds the
// name, so a purge never pulls a tombstone from under a recorded restore.
func (s *Store) PurgeDeletedSecret(ctx context.Context, tenantID, name string) (bool, error) {
	var purged bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		purged, err = purgeDeletedSecretTx(ctx, tx, tenantID, name, time.Time{})
		return err
	})
	return purged, err
}

// purgeDeletedSecretTx purges one tombstone under the name's lock, unless a
// command or batch holds the name; a non-zero before purges it only when it
// was deleted before then (the retention sweep).
func purgeDeletedSecretTx(ctx context.Context, tx pgx.Tx, tenantID, name string, before time.Time) (bool, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		applicationSecretMutationLockKey(tenantID, name)); err != nil {
		return false, err
	}
	var held bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM application_secret_mutation_fences WHERE tenant_id = $1 AND secret_name = $2)
		    OR EXISTS (SELECT 1 FROM application_secret_import_name_fences WHERE tenant_id = $1 AND secret_name = $2)`,
		tenantID, name).Scan(&held); err != nil {
		return false, err
	}
	if held {
		return false, fmt.Errorf("%w: %s is being changed by another command", ErrApplicationSecretMutationInFlight, name)
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM secret_store_tombstones
		  WHERE tenant_id = $1 AND name = $2 AND ($3::timestamptz IS NULL OR deleted_at < $3)`,
		tenantID, name, nullableTime(before))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func nullableTime(at time.Time) any {
	if at.IsZero() {
		return nil
	}
	return at.UTC()
}

// PurgedDeletedSecret names one tombstone the retention sweep removed, so the
// sweep can audit it in its own tenant.
type PurgedDeletedSecret struct {
	TenantID string
	Name     string
}

// PurgeDeletedSecretsBefore removes, across tenants, at most limit tombstones
// deleted before cutoff, with their sealed history (the deleted-secret retention
// sweep, A236-L4). Each one is purged in its own tenant under the name's lock;
// one a command or batch holds is skipped until a later pass. It returns what
// it removed; the sweep calls it again on its next tick while any remain.
func (s *Store) PurgeDeletedSecretsBefore(ctx context.Context, cutoff time.Time, limit int) ([]PurgedDeletedSecret, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.SystemPool().Query(ctx,
		//trstctl:system-query — cross-tenant by design: the deleted-secret retention sweep finds every tenant's tombstones past the window. It reads tenant ids and names only; each purge then runs in its own tenant's transaction.
		`SELECT tenant_id::text, name FROM secret_store_tombstones
		  WHERE deleted_at < $1
		  ORDER BY deleted_at
		  LIMIT $2`, cutoff.UTC(), limit)
	if err != nil {
		return nil, err
	}
	var candidates []PurgedDeletedSecret
	for rows.Next() {
		var p PurgedDeletedSecret
		if err := rows.Scan(&p.TenantID, &p.Name); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []PurgedDeletedSecret
	for _, p := range candidates {
		var purged bool
		err := s.WithTenant(ctx, p.TenantID, func(tx pgx.Tx) error {
			var err error
			purged, err = purgeDeletedSecretTx(ctx, tx, p.TenantID, p.Name, cutoff)
			return err
		})
		if errors.Is(err, ErrApplicationSecretMutationInFlight) {
			continue
		}
		if err != nil {
			return out, err
		}
		if purged {
			out = append(out, p)
		}
	}
	return out, nil
}

// requireApplicationSecretTombstoneTx checks, under the name's lock, that the
// exact kept deletion a restore names is still kept and that no live secret
// took the name (A236-L4); otherwise the restore finds nothing to bring back.
func requireApplicationSecretTombstoneTx(ctx context.Context, tx pgx.Tx, tenantID, name string, ref ApplicationSecretTombstoneRef) error {
	var version int
	var deletedAt time.Time
	err := tx.QueryRow(ctx,
		`SELECT version, deleted_at FROM secret_store_tombstones WHERE tenant_id = $1 AND name = $2`,
		tenantID, name).Scan(&version, &deletedAt)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (version != ref.Version || !deletedAt.Equal(ref.DeletedAt)) {
		return ErrSecretNotFound
	}
	if err != nil {
		return err
	}
	var live bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM secret_store WHERE tenant_id = $1 AND name = $2)`, tenantID, name).Scan(&live); err != nil {
		return err
	}
	if live {
		return ErrApprovalDrifted
	}
	return nil
}

// ApplicationSecretTombstoneApprovalTargetTx locks a deleted secret's
// tombstone for an approval decision on its restore (A236-L4), under the same
// per-name lock as ApplicationSecretApprovalTargetTx, and returns the version a
// restore would bring back.
func (s *Store) ApplicationSecretTombstoneApprovalTargetTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, name string,
) (version int, exists bool, err error) {
	if tenantID == "" || strings.TrimSpace(name) == "" {
		return 0, false, ErrApprovalDrifted
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		applicationSecretMutationLockKey(tenantID, name)); err != nil {
		return 0, false, err
	}
	err = tx.QueryRow(ctx, `
		SELECT version FROM secret_store_tombstones
		 WHERE tenant_id = $1 AND name = $2
		 FOR UPDATE`, tenantID, name).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return version, true, nil
}
