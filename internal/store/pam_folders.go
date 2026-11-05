// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrPAMFolderNotFound is a folder that does not exist (or was deleted).
var ErrPAMFolderNotFound = errors.New("store: PAM folder not found")

// PAMFolder names the access template every account in it takes (A261 part 3).
type PAMFolder struct {
	Name, TemplateID, Description string
	Revision                      int64
	SavedBy                       string
	SavedAt                       time.Time
	DeletedAt                     *time.Time
}

const pamFolderColumns = `name, template_id, description, revision, saved_by, saved_at, deleted_at`

func scanPAMFolder(row pgx.Row) (PAMFolder, error) {
	var f PAMFolder
	err := row.Scan(&f.Name, &f.TemplateID, &f.Description, &f.Revision, &f.SavedBy, &f.SavedAt, &f.DeletedAt)
	return f, err
}

// ApplyPAMFolderSavedTx projects pam.folder.saved at its revision. Saving a
// deleted folder's name again brings it back.
func (s *Store) ApplyPAMFolderSavedTx(ctx context.Context, tx pgx.Tx, tenantID string, f PAMFolder) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO pam_folders AS cur (tenant_id, name, template_id, description, revision, saved_by, saved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, name) DO UPDATE SET
		    template_id = EXCLUDED.template_id, description = EXCLUDED.description, revision = EXCLUDED.revision,
		    saved_by = EXCLUDED.saved_by, saved_at = EXCLUDED.saved_at, deleted_at = NULL
		  WHERE cur.revision < EXCLUDED.revision`,
		tenantID, f.Name, f.TemplateID, f.Description, f.Revision, f.SavedBy, f.SavedAt.UTC())
	return err
}

// ApplyPAMFolderDeletedTx projects pam.folder.deleted at its revision.
func (s *Store) ApplyPAMFolderDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, name string, revision int64, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_folders SET deleted_at = $4, revision = $3
		WHERE tenant_id = $1 AND name = $2 AND revision < $3`, tenantID, name, revision, at.UTC())
	return err
}

// GetPAMFolder returns a live folder.
func (s *Store) GetPAMFolder(ctx context.Context, tenantID, name string) (PAMFolder, error) {
	f, err := s.getPAMFolder(ctx, tenantID, name)
	if err == nil && f.DeletedAt != nil {
		return PAMFolder{}, ErrPAMFolderNotFound
	}
	return f, err
}

// GetPAMFolderAnyState returns a folder, live or deleted: its revision orders
// the next save or delete.
func (s *Store) GetPAMFolderAnyState(ctx context.Context, tenantID, name string) (PAMFolder, error) {
	return s.getPAMFolder(ctx, tenantID, name)
}

func (s *Store) getPAMFolder(ctx context.Context, tenantID, name string) (PAMFolder, error) {
	var f PAMFolder
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		f, err = scanPAMFolder(tx.QueryRow(ctx, `SELECT `+pamFolderColumns+` FROM pam_folders WHERE tenant_id = $1 AND name = $2`,
			tenantID, name))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMFolder{}, ErrPAMFolderNotFound
	}
	return f, err
}

// ListPAMFolders returns a tenant's live folders by name.
func (s *Store) ListPAMFolders(ctx context.Context, tenantID string) ([]PAMFolder, error) {
	out := []PAMFolder{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pamFolderColumns+` FROM pam_folders WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY name`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			f, err := scanPAMFolder(rows)
			if err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// CountPAMTargetsInFolder counts the registered targets (enabled or not) a
// folder holds.
func (s *Store) CountPAMTargetsInFolder(ctx context.Context, tenantID, folder string) (int, error) {
	var n int
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM pam_targets WHERE tenant_id = $1 AND folder = $2`, tenantID, folder).Scan(&n)
	})
	return n, err
}

// WithPAMCatalogLock serializes folder membership and deletion across replicas.
// Contention rejects immediately rather than holding request-pool connections.
// The transaction holds only the advisory fence; changes still use events and
// their projections. The key includes tenant_id, so tenants do not share a lock.
func (s *Store) WithPAMCatalogLock(ctx context.Context, tenantID string, fn func() error) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var acquired bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))`,
			"trstctl:pam-catalog:v1:"+tenantID).Scan(&acquired); err != nil {
			return err
		}
		if !acquired {
			return fmt.Errorf("%w: PAM account configuration is in use; retry", ErrDatastoreBusy)
		}
		return fn()
	})
}
