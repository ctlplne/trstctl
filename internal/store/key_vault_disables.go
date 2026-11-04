// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// Key Vault disables (N2): the projections of
// certificate.key_vault_disable_requested and certificate.key_vault_disabled.

// KeyVaultDisableDestination is the outbox destination of a disable.
const KeyVaultDisableDestination = "keyvault.certificate.disable"

// KeyVaultDisableJobKey is the outbox job a disable queues.
func KeyVaultDisableJobKey(id string) string { return "kv-disable:" + id }

// KeyVaultDisable is one request to disable a certificate version in Key Vault.
type KeyVaultDisable struct {
	ID             string
	CertificateID  string
	ResourceID     string
	SourceID       string
	Reason         string
	RequestedBy    string
	RequestedAt    time.Time
	Disabled       bool
	DisabledAt     *time.Time
	VaultUpdatedAt *time.Time
	// JobStatus and JobError are the outbox job's state while not disabled.
	JobStatus string
	JobError  string
}

func keyVaultSequence(sequence uint64) (int64, error) {
	if sequence == 0 || sequence > math.MaxInt64 {
		return 0, fmt.Errorf("store: Key Vault disable event sequence %d is out of range", sequence)
	}
	return int64(sequence), nil // #nosec G115 -- bounded above (CWE-190)
}

// ApplyKeyVaultDisableRequestedTx projects a requested disable. A replay adds nothing.
func (s *Store) ApplyKeyVaultDisableRequestedTx(ctx context.Context, tx pgx.Tx, tenantID string, d KeyVaultDisable, sequence uint64) error {
	seq, err := keyVaultSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO certificate_key_vault_disables (tenant_id, id, certificate_id, resource_id, source_id, reason, requested_by,
		                                            requested_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, id) DO NOTHING`,
		tenantID, d.ID, d.CertificateID, d.ResourceID, d.SourceID, d.Reason, d.RequestedBy, d.RequestedAt.UTC(), seq)
	return err
}

// ApplyKeyVaultDisabledTx records that the vault read the version back disabled.
func (s *Store) ApplyKeyVaultDisabledTx(ctx context.Context, tx pgx.Tx, tenantID, id string, vaultUpdated *time.Time, at time.Time, sequence uint64) error {
	seq, err := keyVaultSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE certificate_key_vault_disables SET disabled = true, disabled_at = $3, vault_updated_at = $4,
		event_sequence = $5 WHERE tenant_id = $1 AND id = $2 AND NOT disabled`, tenantID, id, at.UTC(), vaultUpdated, seq)
	return err
}

// GetKeyVaultDisable reads one disable with its outbox job's state.
func (s *Store) GetKeyVaultDisable(ctx context.Context, tenantID, id string) (KeyVaultDisable, error) {
	out, err := s.listKeyVaultDisables(ctx, tenantID, "d.id = $2", id)
	if err != nil {
		return KeyVaultDisable{}, err
	}
	if len(out) == 0 {
		return KeyVaultDisable{}, pgx.ErrNoRows
	}
	return out[0], nil
}

// ListKeyVaultDisables lists a certificate's disables, newest first.
func (s *Store) ListKeyVaultDisables(ctx context.Context, tenantID, certificateID string) ([]KeyVaultDisable, error) {
	return s.listKeyVaultDisables(ctx, tenantID, "d.certificate_id = $2", certificateID)
}

func (s *Store) listKeyVaultDisables(ctx context.Context, tenantID, where, arg string) ([]KeyVaultDisable, error) {
	out := []KeyVaultDisable{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.id::text, d.certificate_id::text, d.resource_id, d.source_id::text, d.reason,
			d.requested_by, d.requested_at, d.disabled, d.disabled_at, d.vault_updated_at, coalesce(o.status, ''), coalesce(o.last_error, '')
			  FROM certificate_key_vault_disables d
			  LEFT JOIN outbox o ON o.tenant_id = d.tenant_id AND o.destination = '`+KeyVaultDisableDestination+`'
			   AND o.idempotency_key = 'kv-disable:' || d.id::text
			 WHERE d.tenant_id = $1 AND `+where+` ORDER BY d.requested_at DESC, d.id LIMIT 100`, tenantID, arg)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d KeyVaultDisable
			if err := rows.Scan(&d.ID, &d.CertificateID, &d.ResourceID, &d.SourceID, &d.Reason, &d.RequestedBy, &d.RequestedAt,
				&d.Disabled, &d.DisabledAt, &d.VaultUpdatedAt, &d.JobStatus, &d.JobError); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}
