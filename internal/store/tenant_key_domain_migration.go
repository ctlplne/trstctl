// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// tenantKeyDomainCiphertextStages is the fixed, ordered hot-state inventory for
// a tenant-domain migration. Each item names one column whose populated values
// may contain a CSL container directly or nested inside JSON. New persisted
// secret-bearing columns must join this list and the completeness test.
var tenantKeyDomainCiphertextStages = []string{
	"credentials.sealed",
	"secret_store.sealed",
	"secret_store_versions.sealed",
	"secret_shares.sealed",
	"dynamic_secret_leases.sealed_preparation",
	"dynamic_secret_leases.sealed_credential",
	"code_signing_operations.sealed_command",
	"idempotency_keys.result",
	"outbox.payload",
}

// TenantKeyDomainCiphertextMigrationStages returns a copy of the ordered
// inventory so callers cannot mutate the custody boundary at runtime.
func TenantKeyDomainCiphertextMigrationStages() []string {
	return append([]string(nil), tenantKeyDomainCiphertextStages...)
}

// TenantKeyDomainCiphertextTransform rewraps a persisted ciphertext container
// without opening its payload plaintext. unchanged is valid for public outbox
// payloads and for rows already authenticated under the destination domain.
type TenantKeyDomainCiphertextTransform func(before []byte) (after []byte, changed bool, err error)

// RewriteTenantKeyDomainCiphertextStage rewrites one fixed ciphertext column in
// one RLS-scoped transaction while holding the tenant's exclusive key-domain
// fence. A crash rolls back the complete column. A later retry is byte-safe
// because the transform must recognize already-migrated destination containers.
func (s *Store) RewriteTenantKeyDomainCiphertextStage(
	ctx context.Context,
	tenantID, stage string,
	transform TenantKeyDomainCiphertextTransform,
) (int64, error) {
	if tenantID == "" {
		return 0, errors.New("store: tenant key-domain migration requires tenant_id (AN-1)")
	}
	if transform == nil {
		return 0, errors.New("store: tenant key-domain migration transform is required")
	}
	selectSQL, updateSQL, ok := tenantKeyDomainCiphertextStageSQL(stage)
	if !ok {
		return 0, fmt.Errorf("store: unsupported tenant key-domain migration stage %q", stage)
	}

	var changed int64
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := s.LockTenantKeyDomainExclusiveTx(ctx, tx, tenantID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, selectSQL, tenantID)
		if err != nil {
			return fmt.Errorf("store: select tenant ciphertext stage %s: %w", stage, err)
		}
		type candidate struct {
			rowID  string
			before []byte
		}
		candidates := make([]candidate, 0)
		for rows.Next() {
			var item candidate
			if err := rows.Scan(&item.rowID, &item.before); err != nil {
				rows.Close()
				return fmt.Errorf("store: scan tenant ciphertext stage %s: %w", stage, err)
			}
			candidates = append(candidates, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("store: iterate tenant ciphertext stage %s: %w", stage, err)
		}
		rows.Close()

		for _, item := range candidates {
			after, rewrite, err := transform(append([]byte(nil), item.before...))
			if err != nil {
				return fmt.Errorf("store: transform tenant ciphertext stage %s: %w", stage, err)
			}
			if !rewrite {
				if !bytes.Equal(after, item.before) {
					return fmt.Errorf("store: unchanged tenant ciphertext stage %s returned different bytes", stage)
				}
				continue
			}
			if len(after) == 0 || bytes.Equal(after, item.before) {
				return fmt.Errorf("store: changed tenant ciphertext stage %s returned invalid bytes", stage)
			}
			command, err := tx.Exec(ctx, updateSQL, after, tenantID, item.rowID, item.before)
			if err != nil {
				return fmt.Errorf("store: update tenant ciphertext stage %s: %w", stage, err)
			}
			if command.RowsAffected() != 1 {
				return fmt.Errorf("store: tenant ciphertext stage %s changed while fenced", stage)
			}
			changed++
		}
		return nil
	})
	return changed, err
}

func tenantKeyDomainCiphertextStageSQL(stage string) (selectSQL, updateSQL string, ok bool) {
	switch stage {
	case "credentials.sealed":
		return `SELECT ctid::text, sealed FROM credentials WHERE tenant_id = $1 AND octet_length(sealed) > 0 FOR UPDATE`,
			`UPDATE credentials SET sealed = $1 WHERE tenant_id = $2 AND ctid = $3::tid AND sealed = $4`, true
	case "secret_store.sealed":
		return `SELECT ctid::text, sealed FROM secret_store WHERE tenant_id = $1 AND octet_length(sealed) > 0 FOR UPDATE`,
			`UPDATE secret_store SET sealed = $1 WHERE tenant_id = $2 AND ctid = $3::tid AND sealed = $4`, true
	case "secret_store_versions.sealed":
		return `SELECT ctid::text, sealed FROM secret_store_versions WHERE tenant_id = $1 AND octet_length(sealed) > 0 FOR UPDATE`,
			`UPDATE secret_store_versions SET sealed = $1 WHERE tenant_id = $2 AND ctid = $3::tid AND sealed = $4`, true
	case "secret_shares.sealed":
		return `SELECT ctid::text, sealed FROM secret_shares WHERE tenant_id = $1 AND octet_length(sealed) > 0 FOR UPDATE`,
			`UPDATE secret_shares SET sealed = $1 WHERE tenant_id = $2 AND ctid = $3::tid AND sealed = $4`, true
	case "dynamic_secret_leases.sealed_preparation":
		return `SELECT ctid::text, sealed_preparation FROM dynamic_secret_leases WHERE tenant_id = $1 AND octet_length(sealed_preparation) > 0 FOR UPDATE`,
			`UPDATE dynamic_secret_leases SET sealed_preparation = $1 WHERE tenant_id = $2 AND ctid = $3::tid AND sealed_preparation = $4`, true
	case "dynamic_secret_leases.sealed_credential":
		return `SELECT ctid::text, sealed_credential FROM dynamic_secret_leases WHERE tenant_id = $1 AND octet_length(sealed_credential) > 0 FOR UPDATE`,
			`UPDATE dynamic_secret_leases SET sealed_credential = $1 WHERE tenant_id = $2 AND ctid = $3::tid AND sealed_credential = $4`, true
	case "code_signing_operations.sealed_command":
		return `SELECT ctid::text, sealed_command FROM code_signing_operations WHERE tenant_id = $1 AND octet_length(sealed_command) > 0 FOR UPDATE`,
			`UPDATE code_signing_operations SET sealed_command = $1 WHERE tenant_id = $2 AND ctid = $3::tid AND sealed_command = $4`, true
	case "idempotency_keys.result":
		return `SELECT ctid::text, result FROM idempotency_keys WHERE tenant_id = $1 AND result IS NOT NULL AND octet_length(result) > 0 FOR UPDATE`,
			`UPDATE idempotency_keys SET result = $1 WHERE tenant_id = $2 AND ctid = $3::tid AND result = $4`, true
	case "outbox.payload":
		return `SELECT ctid::text, payload FROM outbox WHERE tenant_id = $1 AND octet_length(payload) > 0 FOR UPDATE`,
			`UPDATE outbox SET payload = $1 WHERE tenant_id = $2 AND ctid = $3::tid AND payload = $4`, true
	default:
		return "", "", false
	}
}
