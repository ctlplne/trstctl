// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

// Scoped secret sync (A237): definitions, the destination keys each one
// manages, and the delete commands its reviewed plans queue.

// SecretScopedSyncDeleteDestination is the outbox destination of a scoped
// sync's key deletes.
const SecretScopedSyncDeleteDestination = "secret.scoped-sync.delete" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)

// Scoped sync key states and delete states.
const (
	SecretScopedSyncKeySynced       = "synced"
	SecretScopedSyncKeyDeleteQueued = "delete_queued"

	SecretScopedSyncDeleteQueued  = "queued"
	SecretScopedSyncDeleteDeleted = "deleted"
	SecretScopedSyncDeleteFailed  = "failed"
)

// ErrSecretScopedSyncNotFound is a scoped sync (or delete) that doesn't exist.
var ErrSecretScopedSyncNotFound = errors.New("store: scoped secret sync not found")

// SecretScopedSync is one definition.
type SecretScopedSync struct {
	ID                string
	Name              string
	SourcePrefix      string
	Target            string
	DestinationPrefix string
	KeyTransform      string
	DeleteScope       string
	AdoptExisting     bool
	DefinedBy         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	LastPlanDigest    string
	LastAppliedAt     *time.Time
	// Mode is manual (a reviewed apply) or auto (the reconciler applies a plan
	// with nothing blocked when the sources change or the drift check is due).
	Mode                string
	SourceDigest        string
	LastReconcileAt     *time.Time
	LastReconcileStatus string
	LastReconcileReason string
}

// SecretScopedSyncKey is one destination key a definition manages.
type SecretScopedSyncKey struct {
	SyncID        string
	RemoteKey     string
	SourceName    string
	SourceVersion int
	JobID         string
	State         string
	DeleteID      string
	UpdatedAt     time.Time
}

// SecretScopedSyncDelete is one queued delete of a managed key.
type SecretScopedSyncDelete struct {
	ID          string
	SyncID      string
	TenantEpoch string
	Target      string
	RemoteKey   string
	State       string
	Error       string
	OutboxID    int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// SecretScopedSyncApplyItem is one item of an applied plan.
type SecretScopedSyncApplyItem struct {
	RemoteKey     string
	SourceName    string
	SourceVersion int
	Action        string // create | update | delete
	JobID         string
	DeleteID      string
}

// SecretScopedSyncDeleteOutboxKey is the one outbox identity of a delete.
func SecretScopedSyncDeleteOutboxKey(tenantEpoch, id string) string {
	return SecretScopedSyncDeleteDestination + ":" + tenantEpoch + ":" + id
}

// ApplySecretScopedSyncDefinedTx projects a definition (create or replace).
func (s *Store) ApplySecretScopedSyncDefinedTx(ctx context.Context, tx pgx.Tx, tenantID string, d SecretScopedSync, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	mode := d.Mode
	if mode == "" {
		mode = "manual"
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO secret_scoped_syncs (tenant_id, id, name, source_prefix, target, destination_prefix, key_transform,
		                                 delete_scope, adopt_existing, defined_by, created_at, updated_at, event_sequence, mode)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, $12, $13)
		ON CONFLICT (tenant_id, id) DO UPDATE
		   SET name = excluded.name, source_prefix = excluded.source_prefix, target = excluded.target,
		       destination_prefix = excluded.destination_prefix, key_transform = excluded.key_transform,
		       delete_scope = excluded.delete_scope, adopt_existing = excluded.adopt_existing,
		       defined_by = excluded.defined_by, updated_at = excluded.updated_at, event_sequence = excluded.event_sequence,
		       mode = excluded.mode
		 WHERE secret_scoped_syncs.event_sequence < excluded.event_sequence`,
		tenantID, d.ID, d.Name, d.SourcePrefix, d.Target, d.DestinationPrefix, d.KeyTransform, d.DeleteScope,
		d.AdoptExisting, d.DefinedBy, d.UpdatedAt.UTC(), seq, mode)
	return err
}

// ApplySecretScopedSyncModeSetTx switches a definition between manual and auto.
func (s *Store) ApplySecretScopedSyncModeSetTx(ctx context.Context, tx pgx.Tx, tenantID, id, mode string, at time.Time, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE secret_scoped_syncs SET mode = $3, updated_at = $4, event_sequence = $5
		 WHERE tenant_id = $1 AND id::text = $2 AND event_sequence < $5`, tenantID, id, mode, at.UTC(), seq)
	return err
}

// ApplySecretScopedSyncReconciledTx records what the reconciler last did with a
// definition and the source set it saw.
func (s *Store) ApplySecretScopedSyncReconciledTx(ctx context.Context, tx pgx.Tx, tenantID, id, status, reason, sourceDigest string, at time.Time, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE secret_scoped_syncs
		   SET last_reconcile_at = $3, last_reconcile_status = $4, last_reconcile_reason = $5, source_digest = $6,
		       event_sequence = $7
		 WHERE tenant_id = $1 AND id::text = $2 AND event_sequence < $7`, tenantID, id, at.UTC(), status, reason, sourceDigest, seq)
	return err
}

// SecretScopedSyncSourceDigest fingerprints the names and versions under a
// source prefix, so the reconciler re-plans only when they changed.
func (s *Store) SecretScopedSyncSourceDigest(ctx context.Context, tenantID, prefix string) (string, error) {
	var listing string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT coalesce(string_agg(name || ':' || version::text, ',' ORDER BY name), '')
			  FROM secret_store WHERE tenant_id = $1 AND left(name, char_length($2)) = $2`, tenantID, prefix).Scan(&listing)
	})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex([]byte(prefix + "\x00" + listing)), nil
}

// TenantsWithAutoScopedSyncs lists tenants holding an auto scoped sync.
func (s *Store) TenantsWithAutoScopedSyncs(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants hold an auto scoped sync so the leader-only reconciler can visit each tenant under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM secret_scoped_syncs WHERE mode = 'auto' ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		out = append(out, tenantID)
	}
	return out, rows.Err()
}

// ApplySecretScopedSyncRemovedTx removes a definition and its key records; the
// destination keys themselves stay where they are.
func (s *Store) ApplySecretScopedSyncRemovedTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	_, err := tx.Exec(ctx, `DELETE FROM secret_scoped_syncs WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// ApplySecretScopedSyncAppliedTx records an applied plan: creates and updates
// become managed keys with their sync job, and each delete becomes a queued
// command with its outbox intent in this same transaction (AN-6).
func (s *Store) ApplySecretScopedSyncAppliedTx(ctx context.Context, tx pgx.Tx, tenantID, tenantEpoch, syncID, target, planDigest string,
	items []SecretScopedSyncApplyItem, at time.Time, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	if tenantEpoch == "" || syncID == "" || target == "" || len(planDigest) != 64 || at.IsZero() {
		return errors.New("store: a scoped sync apply is incomplete")
	}
	tag, err := tx.Exec(ctx, `
		UPDATE secret_scoped_syncs SET last_plan_digest = $3, last_applied_at = $4, event_sequence = $5
		 WHERE tenant_id = $1 AND id = $2 AND event_sequence < $5`, tenantID, syncID, planDigest, at.UTC(), seq)
	if err != nil {
		return err
	}
	defined := tag.RowsAffected() == 1
	for _, item := range items {
		switch item.Action {
		case "create", "update":
			if !defined {
				continue
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO secret_scoped_sync_keys (tenant_id, sync_id, remote_key, source_name, source_version, job_id,
				                                     state, delete_id, updated_at, event_sequence)
				VALUES ($1, $2, $3, $4, $5, $6, 'synced', NULL, $7, $8)
				ON CONFLICT (tenant_id, sync_id, remote_key) DO UPDATE
				   SET source_name = excluded.source_name, source_version = excluded.source_version,
				       job_id = excluded.job_id, state = 'synced', delete_id = NULL,
				       updated_at = excluded.updated_at, event_sequence = excluded.event_sequence
				 WHERE secret_scoped_sync_keys.event_sequence < excluded.event_sequence`,
				tenantID, syncID, item.RemoteKey, item.SourceName, item.SourceVersion, item.JobID, at.UTC(), seq); err != nil {
				return err
			}
		case "delete":
			if item.DeleteID == "" || item.RemoteKey == "" {
				return errors.New("store: a scoped sync delete is incomplete")
			}
			payload, err := json.Marshal(struct {
				TenantEpoch string `json:"tenant_epoch"`
				ID          string `json:"id"`
			}{tenantEpoch, item.DeleteID})
			if err != nil {
				return err
			}
			outboxID, err := ensureSecretIntegrationOutboxTx(ctx, tx, tenantID, SecretScopedSyncDeleteDestination,
				"secret.scoped-sync:"+target, SecretScopedSyncDeleteOutboxKey(tenantEpoch, item.DeleteID), payload)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO secret_scoped_sync_deletes (tenant_id, id, sync_id, tenant_epoch, target, remote_key, state,
				                                        outbox_id, created_at, updated_at, event_sequence)
				VALUES ($1, $2, $3, $4, $5, $6, 'queued', $7, $8, $8, $9)
				ON CONFLICT (tenant_id, id) DO NOTHING`,
				tenantID, item.DeleteID, syncID, tenantEpoch, target, item.RemoteKey, outboxID, at.UTC(), seq); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				UPDATE secret_scoped_sync_keys SET state = 'delete_queued', delete_id = $4, updated_at = $5, event_sequence = $6
				 WHERE tenant_id = $1 AND sync_id = $2 AND remote_key = $3 AND event_sequence < $6`,
				tenantID, syncID, item.RemoteKey, item.DeleteID, at.UTC(), seq); err != nil {
				return err
			}
		default:
			return errors.New("store: a scoped sync apply item has an unknown action")
		}
	}
	return nil
}

// ApplySecretScopedSyncKeyDeletedTx settles a delete: the key leaves the
// definition's managed set.
func (s *Store) ApplySecretScopedSyncKeyDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, deleteID string, at time.Time, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE secret_scoped_sync_deletes SET state = 'deleted', updated_at = $3, event_sequence = $4
		 WHERE tenant_id = $1 AND id = $2 AND state = 'queued'`, tenantID, deleteID, at.UTC(), seq); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM secret_scoped_sync_keys WHERE tenant_id = $1 AND delete_id = $2`, tenantID, deleteID)
	return err
}

// ApplySecretScopedSyncDeleteFailedTx records a delete that exhausted its
// retries; the key stays managed so the next plan proposes it again.
func (s *Store) ApplySecretScopedSyncDeleteFailedTx(ctx context.Context, tx pgx.Tx, tenantID, deleteID, reason string, at time.Time, sequence uint64) error {
	seq, err := secretProjectSequence(sequence)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE secret_scoped_sync_deletes SET state = 'failed', error = $3, updated_at = $4, event_sequence = $5
		 WHERE tenant_id = $1 AND id = $2 AND state = 'queued'`, tenantID, deleteID, reason, at.UTC(), seq); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE secret_scoped_sync_keys SET state = 'synced', delete_id = NULL, updated_at = $3
		 WHERE tenant_id = $1 AND delete_id = $2`, tenantID, deleteID, at.UTC())
	return err
}

// #nosec G101 -- SQL column list, no credential (CWE-798)
const secretScopedSyncColumns = `id::text, name, source_prefix, target, destination_prefix, key_transform, delete_scope,
	adopt_existing, defined_by, created_at, updated_at, last_plan_digest, last_applied_at, mode, source_digest,
	last_reconcile_at, last_reconcile_status, last_reconcile_reason`

func scanSecretScopedSync(row pgx.Row) (SecretScopedSync, error) {
	var d SecretScopedSync
	err := row.Scan(&d.ID, &d.Name, &d.SourcePrefix, &d.Target, &d.DestinationPrefix, &d.KeyTransform, &d.DeleteScope,
		&d.AdoptExisting, &d.DefinedBy, &d.CreatedAt, &d.UpdatedAt, &d.LastPlanDigest, &d.LastAppliedAt, &d.Mode,
		&d.SourceDigest, &d.LastReconcileAt, &d.LastReconcileStatus, &d.LastReconcileReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrSecretScopedSyncNotFound
	}
	return d, err
}

// GetSecretScopedSync reads one definition.
func (s *Store) GetSecretScopedSync(ctx context.Context, tenantID, id string) (SecretScopedSync, error) {
	var d SecretScopedSync
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		d, err = scanSecretScopedSync(tx.QueryRow(ctx, `SELECT `+secretScopedSyncColumns+`
			FROM secret_scoped_syncs WHERE tenant_id = $1 AND id::text = $2`, tenantID, id))
		return err
	})
	return d, err
}

// ListSecretScopedSyncs lists the tenant's definitions by name.
func (s *Store) ListSecretScopedSyncs(ctx context.Context, tenantID string) ([]SecretScopedSync, error) {
	var out []SecretScopedSync
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+secretScopedSyncColumns+`
			FROM secret_scoped_syncs WHERE tenant_id = $1 ORDER BY name`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			d, err := scanSecretScopedSync(rows)
			if err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// ListSecretScopedSyncKeys lists the keys a definition manages, by key.
func (s *Store) ListSecretScopedSyncKeys(ctx context.Context, tenantID, syncID string) ([]SecretScopedSyncKey, error) {
	var out []SecretScopedSyncKey
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT sync_id::text, remote_key, source_name, source_version, job_id, state, coalesce(delete_id::text, ''), updated_at
			  FROM secret_scoped_sync_keys WHERE tenant_id = $1 AND sync_id::text = $2 ORDER BY remote_key`, tenantID, syncID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k SecretScopedSyncKey
			if err := rows.Scan(&k.SyncID, &k.RemoteKey, &k.SourceName, &k.SourceVersion, &k.JobID, &k.State, &k.DeleteID, &k.UpdatedAt); err != nil {
				return err
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, err
}

// GetSecretScopedSyncDelete reads one delete command.
func (s *Store) GetSecretScopedSyncDelete(ctx context.Context, tenantID, id string) (SecretScopedSyncDelete, error) {
	var d SecretScopedSyncDelete
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var outbox *int64
		err := tx.QueryRow(ctx, `
			SELECT id::text, sync_id::text, tenant_epoch, target, remote_key, state, error, outbox_id, created_at, updated_at
			  FROM secret_scoped_sync_deletes WHERE tenant_id = $1 AND id::text = $2`, tenantID, id).
			Scan(&d.ID, &d.SyncID, &d.TenantEpoch, &d.Target, &d.RemoteKey, &d.State, &d.Error, &outbox, &d.CreatedAt, &d.UpdatedAt)
		if outbox != nil {
			d.OutboxID = *outbox
		}
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrSecretScopedSyncNotFound
	}
	return d, err
}
