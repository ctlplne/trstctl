// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CryptoAsset is one classified cryptographic observation in the CBOM (F52).
type CryptoAsset struct {
	ID                string
	TenantID          string
	Kind              string
	Location          string
	Algorithm         string
	KeyBits           int
	Protocol          string
	Cipher            string
	Library           string
	Strength          string
	QuantumVulnerable bool
	OutOfPolicy       bool
	Reasons           []string
	CreatedAt         time.Time
}

// signature identifies an asset within a tenant: the kind, location, and the
// specific crypto fact it describes. Re-scanning the same usage refreshes the
// existing row rather than duplicating it.
func (a CryptoAsset) Signature() string {
	return strings.Join([]string{a.Kind, a.Location, a.Algorithm, strconv.Itoa(a.KeyBits), a.Protocol, a.Cipher}, "|")
}

// StableCryptoAssetID derives the same UUID every time for a tenant-scoped asset
// signature. A CBOM row is a projection of cbom.asset.observed, so replaying the log
// must not mint a different primary key each rebuild.
func StableCryptoAssetID(tenantID, signature string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("trstctl:crypto-asset:"+tenantID+":"+signature)).String()
}

// UpsertCryptoAsset inserts or refreshes a crypto asset by (tenant, signature),
// returning it with its id and created_at. Tenant-scoped (RLS-enforced).
func (s *Store) UpsertCryptoAsset(ctx context.Context, a CryptoAsset) (CryptoAsset, error) {
	reasons := a.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	signature := a.Signature()
	if a.ID == "" {
		a.ID = StableCryptoAssetID(a.TenantID, signature)
	}
	err := s.WithTenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO crypto_assets
			        (id, tenant_id, signature, kind, location, algorithm, key_bits, protocol, cipher,
			         library, strength, quantum_vulnerable, out_of_policy, reasons)
			 VALUES ($14, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			 ON CONFLICT (tenant_id, signature) DO UPDATE
			    SET key_bits = EXCLUDED.key_bits, library = EXCLUDED.library, strength = EXCLUDED.strength,
			        quantum_vulnerable = EXCLUDED.quantum_vulnerable, out_of_policy = EXCLUDED.out_of_policy,
			        reasons = EXCLUDED.reasons
			 RETURNING id::text, created_at`,
			a.TenantID, signature, a.Kind, a.Location, a.Algorithm, a.KeyBits, a.Protocol, a.Cipher,
			a.Library, a.Strength, a.QuantumVulnerable, a.OutOfPolicy, reasons, a.ID).
			Scan(&a.ID, &a.CreatedAt)
	})
	return a, err
}

// ApplyCryptoAssetObservedTx projects one cbom.asset.observed event on the caller's
// transaction. It is idempotent by (tenant_id, signature), matching UpsertCryptoAsset.
func (s *Store) ApplyCryptoAssetObservedTx(ctx context.Context, tx pgx.Tx, a CryptoAsset, observedAt time.Time) error {
	reasons := a.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	signature := a.Signature()
	if a.ID == "" {
		a.ID = StableCryptoAssetID(a.TenantID, signature)
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO crypto_assets
		        (id, tenant_id, signature, kind, location, algorithm, key_bits, protocol, cipher,
		         library, strength, quantum_vulnerable, out_of_policy, reasons, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		 ON CONFLICT (tenant_id, signature) DO UPDATE
		    SET key_bits = EXCLUDED.key_bits, library = EXCLUDED.library, strength = EXCLUDED.strength,
		        quantum_vulnerable = EXCLUDED.quantum_vulnerable, out_of_policy = EXCLUDED.out_of_policy,
		        reasons = EXCLUDED.reasons`,
		a.ID, a.TenantID, signature, a.Kind, a.Location, a.Algorithm, a.KeyBits, a.Protocol, a.Cipher,
		a.Library, a.Strength, a.QuantumVulnerable, a.OutOfPolicy, reasons, observedAt)
	return err
}

// ApplyCryptoAssetMigratedTx projects a licensed crypto migration completion
// onto the existing CBOM row. The identity of the observed asset stays stable
// (same id); only the public crypto fact changes from the original algorithm to
// the served transition algorithm. Tenant_id is both in the RLS context and in
// the predicate (AN-1).
func (s *Store) ApplyCryptoAssetMigratedTx(ctx context.Context, tx pgx.Tx, a CryptoAsset, observedAt time.Time) error {
	return s.replaceCryptoAssetTx(ctx, tx, a, observedAt, false)
}

// ApplyCryptoAssetRolledBackTx restores the previous public crypto fact for a CBOM
// row after a migration rollback. Like migration completion, this is a projection of
// an immutable event rather than an imperative read-model mutation.
func (s *Store) ApplyCryptoAssetRolledBackTx(ctx context.Context, tx pgx.Tx, a CryptoAsset, observedAt time.Time) error {
	return s.replaceCryptoAssetTx(ctx, tx, a, observedAt, true)
}

func (s *Store) replaceCryptoAssetTx(ctx context.Context, tx pgx.Tx, a CryptoAsset, observedAt time.Time, restoreMissing bool) error {
	reasons := a.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	signature := a.Signature()
	// A scan can observe both a weak fact and the already-approved fact that a
	// migration will converge on (for example TLSv1 plus TLSv1.3 in one listener
	// directive). The unique tenant/signature index correctly prevents duplicate
	// read-model facts. On forward migration, retain the already-observed desired
	// fact and remove the now-obsolete weak selected row. Rollback can recreate
	// that selected row from the immutable event payload.
	merged, err := tx.Exec(ctx,
		`DELETE FROM crypto_assets selected
		  WHERE selected.tenant_id = $1 AND selected.id = $3
		    AND EXISTS (SELECT 1 FROM crypto_assets desired
		                 WHERE desired.tenant_id = $1 AND desired.signature = $2 AND desired.id <> $3)`,
		a.TenantID, signature, a.ID)
	if err != nil {
		return err
	}
	if merged.RowsAffected() != 0 {
		return nil
	}
	tag, err := tx.Exec(ctx,
		`UPDATE crypto_assets
		    SET signature = $3, kind = $4, location = $5, algorithm = $6, key_bits = $7,
		        protocol = $8, cipher = $9, library = $10, strength = $11,
		        quantum_vulnerable = $12, out_of_policy = $13, reasons = $14
		  WHERE tenant_id = $1 AND id = $2`,
		a.TenantID, a.ID, signature, a.Kind, a.Location, a.Algorithm, a.KeyBits,
		a.Protocol, a.Cipher, a.Library, a.Strength, a.QuantumVulnerable, a.OutOfPolicy, reasons)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if restoreMissing {
			return s.ApplyCryptoAssetObservedTx(ctx, tx, a, observedAt)
		}
		return pgx.ErrNoRows
	}
	return nil
}

// ListCryptoAssets returns every crypto asset for the tenant, ordered.
func (s *Store) ListCryptoAssets(ctx context.Context, tenantID string) ([]CryptoAsset, error) {
	var out []CryptoAsset
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, kind, location, algorithm, key_bits, protocol, cipher,
			        library, strength, quantum_vulnerable, out_of_policy, reasons, created_at
			   FROM crypto_assets WHERE tenant_id = $1 ORDER BY location, algorithm, protocol, cipher`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a CryptoAsset
			if err := rows.Scan(&a.ID, &a.TenantID, &a.Kind, &a.Location, &a.Algorithm, &a.KeyBits,
				&a.Protocol, &a.Cipher, &a.Library, &a.Strength, &a.QuantumVulnerable, &a.OutOfPolicy,
				&a.Reasons, &a.CreatedAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
