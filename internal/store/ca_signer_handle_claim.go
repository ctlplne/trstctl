// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

// caSignerClaimPartition is a fixed non-customer RLS partition. The handle
// digest is global because the signer keystore is global. Tenant data never
// becomes visible to another customer through the conflict response.
const caSignerClaimPartition = "00000000-0000-0000-0000-000000000003"

var ErrCASignerHandleClaimed = errors.New("store: CA signer handle is already claimed")

// ClaimCASignerHandle is a durable first-writer fence. It commits before key
// generation or ca.authority.* append, so an append/SQL gap cannot let another
// tenant acquire the same signer-held private key. A retry of the same ceremony
// is idempotent; a different ceremony, including one in the same tenant, is not.
func (s *Store) ClaimCASignerHandle(ctx context.Context, tenantID, ceremonyID, handle string) error {
	if tenantID == "" || tenantID == caSignerClaimPartition || ceremonyID == "" || handle == "" {
		return errors.New("store: CA signer claim requires tenant, ceremony and handle")
	}
	hash := crypto.SHA256Hex([]byte(handle))
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := lockLiveTenantRegistrationTx(ctx, tx, tenantID); err != nil {
			return err
		}
		if err := setCASignerClaimScopeTx(ctx, tx); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO ca_signer_handle_claims
		        (tenant_id, handle_sha256, owner_tenant_id, owner_ceremony_id)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (tenant_id, handle_sha256) DO NOTHING`,
			caSignerClaimPartition, hash, tenantID, ceremonyID)
		if err != nil {
			return fmt.Errorf("store: claim CA signer handle: %w", err)
		}
		var ownerTenant, ownerCeremony *string
		var state string
		if err := tx.QueryRow(ctx, `SELECT owner_tenant_id::text, owner_ceremony_id::text, state
			  FROM ca_signer_handle_claims
			 WHERE tenant_id = $1 AND handle_sha256 = $2`,
			caSignerClaimPartition, hash).Scan(&ownerTenant, &ownerCeremony, &state); err != nil {
			return fmt.Errorf("store: read CA signer claim: %w", err)
		}
		if state != "claimed" || ownerTenant == nil || ownerCeremony == nil ||
			*ownerTenant != tenantID || *ownerCeremony != ceremonyID {
			return ErrCASignerHandleClaimed
		}
		return nil
	})
}

func setCASignerClaimScopeTx(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SET LOCAL search_path TO public"); err != nil {
		return fmt.Errorf("store: route CA signer claim partition: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id', $1, true)`, caSignerClaimPartition); err != nil {
		return fmt.Errorf("store: scope CA signer claim partition: %w", err)
	}
	return nil
}

// RetireCASignerHandleClaimsTx scrubs customer ownership during offboard while
// retaining only digests as permanent denial tombstones. This runs under the
// offboard transaction's lifecycle fence, so no concurrent claim can race it.
func RetireCASignerHandleClaimsTx(ctx context.Context, tx pgx.Tx, tenantID string) (int64, error) {
	if tenantID == "" || tenantID == caSignerClaimPartition {
		return 0, errors.New("store: CA signer claim retirement requires customer tenant")
	}
	var priorTenant, priorSearchPath string
	if err := tx.QueryRow(ctx, `SELECT current_setting('trstctl.tenant_id'), current_setting('search_path')`).Scan(&priorTenant, &priorSearchPath); err != nil {
		return 0, err
	}
	if priorTenant != tenantID {
		return 0, errors.New("store: CA signer claim retirement tenant scope changed")
	}
	if err := setCASignerClaimScopeTx(ctx, tx); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `UPDATE ca_signer_handle_claims
		   SET owner_tenant_id = NULL, owner_ceremony_id = NULL, state = 'retired'
		 WHERE tenant_id = $1 AND owner_tenant_id = $2 AND state = 'claimed'`,
		caSignerClaimPartition, tenantID)
	if err != nil {
		return 0, fmt.Errorf("store: retire CA signer claims: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true), set_config('search_path',$2,true)`, priorTenant, priorSearchPath); err != nil {
		return 0, fmt.Errorf("store: restore tenant scope after CA signer claim retirement: %w", err)
	}
	return tag.RowsAffected(), nil
}
