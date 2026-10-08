// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// attestations is independent backup state, but its optional identity FK makes
// PostgreSQL include the whole table in a read-model TRUNCATE ... CASCADE. Hold
// its exact rows in a transaction-local table while identities are rebuilt.
// PostgreSQL drops the copy on commit or rollback, including after a failed
// replay; it is never a second durable authority.
func preserveIndependentAttestationsTx(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx,
		//trstctl:system-query — this cross-tenant system rebuild temporarily preserves independent evidence under the owner role; every row retains tenant_id and the copy is never served.
		`CREATE TEMP TABLE trstctl_rebuild_attestations ON COMMIT DROP AS
		 SELECT * FROM attestations`)
	if err != nil {
		return fmt.Errorf("store: preserve independent attestations before read-model replacement: %w", err)
	}
	return nil
}

func restoreIndependentAttestationsTx(ctx context.Context, tx pgx.Tx) error {
	var conflicts int
	if err := tx.QueryRow(ctx,
		//trstctl:system-query — this cross-tenant system rebuild compares saved independent rows to rebuilt rows; both sides retain tenant_id so conflicting evidence fails.
		`SELECT count(*) FROM pg_temp.trstctl_rebuild_attestations AS saved
		 JOIN attestations AS current ON current.id = saved.id
		 WHERE to_jsonb(current) IS DISTINCT FROM to_jsonb(saved)`).Scan(&conflicts); err != nil {
		return fmt.Errorf("store: compare independent attestations after read-model replacement: %w", err)
	}
	if conflicts != 0 {
		return fmt.Errorf("store: %d rebuilt attestations differ from independent preserved evidence", conflicts)
	}
	if _, err := tx.Exec(ctx,
		//trstctl:system-query — this cross-tenant system rebuild restores exact independent evidence after referenced identities; tenant_id is copied unchanged.
		`INSERT INTO attestations
		 SELECT saved.* FROM pg_temp.trstctl_rebuild_attestations AS saved
		 WHERE NOT EXISTS (SELECT 1 FROM attestations AS current WHERE current.id = saved.id)`); err != nil {
		return fmt.Errorf("store: restore independent attestations after read-model replacement: %w", err)
	}
	var missing int
	if err := tx.QueryRow(ctx,
		//trstctl:system-query — this cross-tenant system rebuild proves every preserved row survived; tenant_id is part of the exact comparison.
		`SELECT count(*) FROM pg_temp.trstctl_rebuild_attestations AS saved
		 LEFT JOIN attestations AS current ON current.id = saved.id AND current.tenant_id = saved.tenant_id
		 WHERE current.id IS NULL`).Scan(&missing); err != nil {
		return fmt.Errorf("store: verify preserved attestations after read-model replacement: %w", err)
	}
	if missing != 0 {
		return fmt.Errorf("store: %d independent attestations missing after read-model replacement", missing)
	}
	return nil
}

// preservedRestoreDrillAttestationTx tells a replay whether this exact signed
// attestation was already committed before TRUNCATE CASCADE. The original
// projection put its alert outbox intent in that same transaction. If the row
// survived in the independent state while the intent no longer exists, the
// completed outbox entry was reclaimed; replay must not queue it again.
func preservedRestoreDrillAttestationTx(ctx context.Context, tx pgx.Tx, a Attestation) (bool, error) {
	var hasSnapshot bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('pg_temp.trstctl_rebuild_attestations') IS NOT NULL`).Scan(&hasSnapshot); err != nil {
		return false, err
	}
	if !hasSnapshot {
		return false, nil
	}
	var sameKind, unbound, exact bool
	err := tx.QueryRow(ctx,
		`SELECT kind = $3, identity_id IS NULL,
		        evidence = $4::jsonb AND verified_at = $5 AND created_at = $6
		   FROM pg_temp.trstctl_rebuild_attestations
		  WHERE tenant_id = $1 AND id = $2`,
		a.TenantID, a.ID, a.Kind, a.Evidence, a.VerifiedAt.UTC(), a.CreatedAt.UTC()).Scan(&sameKind, &unbound, &exact)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !sameKind || !unbound {
		return false, fmt.Errorf("%w: preserved restore-drill attestation differs from signed event", ErrIdempotencyConflict)
	}
	if exact {
		return true, nil
	}
	// The caller verified the immutable event signature before reaching this
	// point. A stored row with altered evidence or timestamps is a corrupt
	// projection, not a reason to keep serving it after a cold rebuild. Remove
	// only this event-backed row from the temporary preservation set so replay
	// restores the signed body and its alert intent. Other independent rows stay.
	if _, err := tx.Exec(ctx,
		`DELETE FROM pg_temp.trstctl_rebuild_attestations
		  WHERE tenant_id = $1 AND id = $2 AND kind = $3 AND identity_id IS NULL`,
		a.TenantID, a.ID, a.Kind); err != nil {
		return false, fmt.Errorf("store: discard corrupt restore-drill projection during replay: %w", err)
	}
	return false, nil
}
