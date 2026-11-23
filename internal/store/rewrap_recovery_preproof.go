// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

// RecoverySnapshotTenantsTx lists only tenant IDs present in this exact
// event-derived staging operation. The owner then processes each tenant with
// explicit tenant predicates; no cross-tenant proof data is returned here.
func (s *Store) RecoverySnapshotTenantsTx(ctx context.Context, tx pgx.Tx, operationID string) ([]string, error) {
	if s == nil || tx == nil {
		return nil, ErrKeyStateAdmissionUnavailable
	}
	if _, err := uuid.Parse(operationID); err != nil {
		return nil, ErrKeyStateAdmissionUnavailable
	}
	//trstctl:system-query — cross-tenant system recovery enumerates tenant_id only for this exact operation; later proof pages and writes use both tenant_id and operation_id predicates.
	rows, err := tx.Query(ctx, `SELECT DISTINCT tenant_id::text
		FROM trstctl_recovery.tenant_key_domain_snapshots
		WHERE operation_id=$1 ORDER BY tenant_id`, operationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenantID)
	}
	return tenants, rows.Err()
}

// ListApplicationSecretReceiptProofPageTx pins the exact independent receipt
// row hash in the rebuild transaction before any read-model TRUNCATE. The
// canonical event and ciphertext authentication are checked by the caller.
func (s *Store) ListApplicationSecretReceiptProofPageTx(
	ctx context.Context, tx pgx.Tx, tenantID, afterEventID string,
) ([]ApplicationSecretRewrapReceipt, error) {
	if s == nil || tx == nil || tenantID == "" {
		return nil, errors.New("store: recovery receipt paging is incomplete")
	}
	rows, err := tx.Query(ctx, `SELECT event_id::text,semantic_sha256,
		coalesce(semantic_sha256_v2,''),to_jsonb(r)::text
		FROM application_secret_mutation_receipts AS r
		WHERE tenant_id=$1 AND ($2='' OR event_id > $2::uuid)
		ORDER BY r.event_id LIMIT $3`,
		tenantID, afterEventID, ApplicationSecretRewrapReceiptPageLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var page []ApplicationSecretRewrapReceipt
	for rows.Next() {
		var receipt ApplicationSecretRewrapReceipt
		var rowJSON string
		if err := rows.Scan(&receipt.EventID, &receipt.DigestV1, &receipt.DigestV2, &rowJSON); err != nil {
			return nil, err
		}
		receipt.RowSHA256 = crypto.SHA256Hex([]byte(rowJSON))
		page = append(page, receipt)
	}
	return page, rows.Err()
}

// RecoveryKeyStateDigestTx binds a proof to the validated staged tenant key
// event and the independently retained deployment key generation. Both are
// re-read after TRUNCATE, under the same owner transaction and A/B locks.
func (s *Store) RecoveryKeyStateDigestTx(ctx context.Context, tx pgx.Tx, tenantID, operationID string) (string, error) {
	if s == nil || tx == nil || tenantID == "" {
		return "", ErrKeyStateAdmissionUnavailable
	}
	if _, err := uuid.Parse(operationID); err != nil {
		return "", ErrKeyStateAdmissionUnavailable
	}
	var kind, snapshotDigest string
	if err := tx.QueryRow(ctx, `SELECT record_kind,snapshot_sha256
		FROM trstctl_recovery.tenant_key_domain_snapshots
		WHERE tenant_id=$1 AND operation_id=$2
		ORDER BY source_sequence DESC LIMIT 1`, tenantID, operationID).
		Scan(&kind, &snapshotDigest); err != nil {
		return "", fmt.Errorf("store: read staged key-state digest: %w", err)
	}
	if kind != "key_domain" && kind != "tenant_registered" {
		return "", errors.New("store: recovery key state belongs to an offboarded lifecycle")
	}
	var deploymentJSON string
	//trstctl:system-query — cross-tenant system recovery reads the one deployment_kek_domain singleton outside tenant RLS; the proof binds only its exact generation and wrapped-key fields.
	err := tx.QueryRow(ctx, `SELECT jsonb_build_object(
		'generation',generation,'wrapper_kind',wrapper_kind,'wrapper_id',wrapper_id,
		'wrapped_kek',wrapped_kek,'next_generation',next_generation,
		'next_wrapper_kind',next_wrapper_kind,'next_wrapper_id',next_wrapper_id,
		'next_wrapped_kek',next_wrapped_kek)::text
		FROM deployment_kek_domain WHERE singleton=true`).Scan(&deploymentJSON)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	return crypto.SHA256Hex([]byte(kind + "\x00" + snapshotDigest + "\x00" + deploymentJSON)), nil
}
