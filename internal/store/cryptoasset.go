// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CryptoAsset is one classified cryptographic observation in the CBOM (F52).
type CryptoAsset struct {
	CertificateFingerprint string
	ID                     string
	TenantID               string
	Kind                   string
	Location               string
	Algorithm              string
	KeyBits                int
	Protocol               string
	Cipher                 string
	Library                string
	Strength               string
	QuantumVulnerable      bool
	OutOfPolicy            bool
	Reasons                []string
	// ImportSource is the CBOM import source whose import last observed
	// this fact (X6-L3); empty for trstctl's own scans.
	ImportSource string
	CreatedAt    time.Time
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
	if err := validateCryptoAssetFingerprint(a); err != nil {
		return a, err
	}
	reasons := a.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	signature := a.Signature()
	if a.ID == "" {
		a.ID = StableCryptoAssetID(a.TenantID, signature)
	}
	err := s.WithTenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		// The direct writer derives the same ID as event replay; join the
		// projector's arbiter lock before either unique index is touched.
		if err := lockUpsertArbiterTx(ctx, tx, "crypto_assets", a.TenantID, signature); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`INSERT INTO crypto_assets
			        (id, tenant_id, signature, kind, location, algorithm, key_bits, protocol, cipher,
			         library, strength, quantum_vulnerable, out_of_policy, reasons, certificate_fingerprint)
			 VALUES ($14, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $15)
			 ON CONFLICT (tenant_id, signature) DO UPDATE
			    SET key_bits = EXCLUDED.key_bits, library = EXCLUDED.library, strength = EXCLUDED.strength,
			        quantum_vulnerable = EXCLUDED.quantum_vulnerable, out_of_policy = EXCLUDED.out_of_policy,
			        reasons = EXCLUDED.reasons, is_active = true, certificate_fingerprint = EXCLUDED.certificate_fingerprint
			 RETURNING id::text, created_at`,
			a.TenantID, signature, a.Kind, a.Location, a.Algorithm, a.KeyBits, a.Protocol, a.Cipher,
			a.Library, a.Strength, a.QuantumVulnerable, a.OutOfPolicy, reasons, a.ID, a.CertificateFingerprint).
			Scan(&a.ID, &a.CreatedAt)
	})
	return a, err
}

// ApplyCryptoAssetObservedTx projects one cbom.asset.observed event on the caller's
// transaction. Asset id handles a fact whose signature changed during migration;
// signature handles independently observed equivalent facts. The stream sequence
// makes both conflict paths monotonic under direct projection plus tail replay.
func (s *Store) ApplyCryptoAssetObservedTx(ctx context.Context, tx pgx.Tx, a CryptoAsset, eventSequence uint64, observedAt time.Time) error {
	if err := validateCryptoAssetFingerprint(a); err != nil {
		return err
	}
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
	sequence, err := cryptoAssetEventSequence(eventSequence)
	if err != nil {
		return err
	}
	// Resolve the immutable asset id first. A migration can change the public
	// crypto fact (and therefore its signature), but an older observation still
	// carries the original id. The sequence predicate makes that delayed replay a
	// no-op instead of letting it move the row backward.
	tag, err := tx.Exec(ctx,
		`UPDATE crypto_assets
		    SET signature = $3, kind = $4, location = $5, algorithm = $6, key_bits = $7,
		        protocol = $8, cipher = $9, library = $10, strength = $11,
		        quantum_vulnerable = $12, out_of_policy = $13, reasons = $14,
		        event_sequence = $15, is_active = true, certificate_fingerprint = $16,
		        import_source = $17
		  WHERE tenant_id = $1 AND id = $2 AND event_sequence <= $15`,
		a.TenantID, a.ID, signature, a.Kind, a.Location, a.Algorithm, a.KeyBits,
		a.Protocol, a.Cipher, a.Library, a.Strength, a.QuantumVulnerable, a.OutOfPolicy,
		reasons, sequence, a.CertificateFingerprint, a.ImportSource)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 0 {
		return nil
	}
	var idExists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM crypto_assets WHERE tenant_id = $1 AND id = $2)`,
		a.TenantID, a.ID).Scan(&idExists); err != nil {
		return err
	}
	if idExists {
		// A newer event already owns this row. This is the normal delayed-tail
		// case after a synchronous migration or rollback projection.
		return nil
	}
	if err := lockUpsertArbiterTx(ctx, tx, "crypto_assets", a.TenantID, signature); err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO crypto_assets
		        (id, tenant_id, signature, kind, location, algorithm, key_bits, protocol, cipher,
		         library, strength, quantum_vulnerable, out_of_policy, reasons, created_at,
		         event_sequence, is_active, certificate_fingerprint, import_source)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, true, $17, $18)
		 ON CONFLICT (tenant_id, signature) DO UPDATE
		    SET key_bits = EXCLUDED.key_bits, library = EXCLUDED.library, strength = EXCLUDED.strength,
		        quantum_vulnerable = EXCLUDED.quantum_vulnerable, out_of_policy = EXCLUDED.out_of_policy,
		        reasons = EXCLUDED.reasons, event_sequence = EXCLUDED.event_sequence, is_active = true, certificate_fingerprint = EXCLUDED.certificate_fingerprint,
		        import_source = EXCLUDED.import_source
		  WHERE EXCLUDED.event_sequence >= crypto_assets.event_sequence`,
		a.ID, a.TenantID, signature, a.Kind, a.Location, a.Algorithm, a.KeyBits, a.Protocol, a.Cipher,
		a.Library, a.Strength, a.QuantumVulnerable, a.OutOfPolicy, reasons, observedAt, sequence, a.CertificateFingerprint, a.ImportSource)
	return err
}

// ApplyCryptoSourceReconciledTx retires facts absent from one complete source
// observation. It runs only as a projection of cbom.source.reconciled; the old
// rows remain as sequence-fenced tombstones for audit and deterministic replay.
func (s *Store) ApplyCryptoSourceReconciledTx(ctx context.Context, tx pgx.Tx, tenantID, sourceKind, location string, observedIDs []string, eventSequence uint64) error {
	if location == "" {
		return errors.New("store: CBOM reconciliation requires a source location")
	}
	var kinds []string
	switch sourceKind {
	case "host-config":
		kinds = []string{"host-config"}
	case "tls-endpoints":
		kinds = []string{"tls-endpoint", "certificate-key"}
	default:
		return fmt.Errorf("store: unsupported CBOM reconciliation source %q", sourceKind)
	}
	if len(observedIDs) > 1024 {
		return errors.New("store: CBOM reconciliation exceeds the finding limit")
	}
	seen := make(map[string]struct{}, len(observedIDs))
	for _, id := range observedIDs {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != id {
			return fmt.Errorf("store: CBOM reconciliation has invalid asset id %q", id)
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("store: CBOM reconciliation repeats asset id %q", id)
		}
		seen[id] = struct{}{}
	}
	sequence, err := cryptoAssetEventSequence(eventSequence)
	if err != nil {
		return err
	}
	// A forged or mismatched observed list must never retire another tenant's or
	// another source's assets. A later event may already have tombstoned a valid
	// reference, so existence and provenance are checked without is_active.
	var matched int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM crypto_assets
		  WHERE tenant_id = $1 AND location = $2 AND kind = ANY($3::text[]) AND id::text = ANY($4::text[])`,
		tenantID, location, kinds, observedIDs).Scan(&matched); err != nil {
		return err
	}
	if matched != len(observedIDs) {
		return errors.New("store: CBOM reconciliation references assets outside its tenant or source")
	}
	_, err = tx.Exec(ctx,
		`UPDATE crypto_assets SET is_active = false, event_sequence = $5
		  WHERE tenant_id = $1 AND location = $2 AND kind = ANY($3::text[])
		    AND NOT (id::text = ANY($4::text[])) AND is_active AND event_sequence < $5`,
		tenantID, location, kinds, observedIDs, sequence)
	return err
}

// importedCryptoAssetKinds are the kinds a CBOM import records (internal/cbom).
var importedCryptoAssetKinds = []string{"imported-algorithm", "imported-certificate", "imported-key", "imported-protocol", "imported-library"}

// cbomImportSourceName is the discovery source name prefix of a CBOM import
// (sourcecatalog.CBOMImportSourcePrefix).
const cbomImportSourceName = "cbom-import:"

// ApplyCryptoImportReconciledTx retires the facts an earlier import of source
// recorded that the import whose observations began at observedFrom did not
// observe again (X6-L3): a newer BOM's dropped assets. It runs only as a
// projection of cbom.import.reconciled. Every fact the import observed was
// projected at a sequence from observedFrom on, so the source's active rows
// below it are exactly what the BOM no longer lists; they stay as
// sequence-fenced tombstones, and a later observation reactivates one.
//
// A row recorded before imports named their source (import_source empty) is
// the source's when its location is under "<source>:" and under no longer
// import source of the tenant, which owns "<source>:<rest>:" itself; it is
// claimed for the source as it is retired.
func (s *Store) ApplyCryptoImportReconciledTx(ctx context.Context, tx pgx.Tx, tenantID, source string, observedFrom, eventSequence uint64) error {
	if source == "" || len(source) > 200 {
		return errors.New("store: CBOM import reconciliation requires its import source")
	}
	if observedFrom == 0 || observedFrom >= eventSequence {
		return fmt.Errorf("store: CBOM import reconciliation observed from sequence %d, not before its own %d", observedFrom, eventSequence)
	}
	from, err := cryptoAssetEventSequence(observedFrom)
	if err != nil {
		return err
	}
	sequence, err := cryptoAssetEventSequence(eventSequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`UPDATE crypto_assets SET is_active = false, event_sequence = $4, import_source = $2
		  WHERE tenant_id = $1 AND is_active AND event_sequence < $3
		    AND (import_source = $2::text
		         OR (import_source = '' AND kind = ANY($5::text[]) AND starts_with(location, $2::text || ':')
		             AND NOT EXISTS (
		                 SELECT 1 FROM discovery_sources d
		                  WHERE d.tenant_id = $1
		                    AND starts_with(d.name, $6::text || $2::text || ':')
		                    AND starts_with(crypto_assets.location, substr(d.name, length($6::text) + 1) || ':'))))`,
		tenantID, source, from, sequence, importedCryptoAssetKinds, cbomImportSourceName)
	return err
}

// CryptoAssetIDsRetiredByImport lists the rows one cbom.import.reconciled
// event (at eventSequence) retired for source (X6-L3).
func (s *Store) CryptoAssetIDsRetiredByImport(ctx context.Context, tenantID, source string, eventSequence uint64) ([]string, error) {
	sequence, err := cryptoAssetEventSequence(eventSequence)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	err = s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text FROM crypto_assets
			  WHERE tenant_id = $1 AND import_source = $2 AND NOT is_active AND event_sequence = $3
			  ORDER BY id`, tenantID, source, sequence)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
}

// ApplyCryptoAssetMigratedTx projects a licensed crypto migration completion
// onto the existing CBOM row. The identity of the observed asset stays stable
// (same id); only the public crypto fact changes from the original algorithm to
// the served transition algorithm. Tenant_id is both in the RLS context and in
// the predicate (AN-1).
func (s *Store) ApplyCryptoAssetMigratedTx(ctx context.Context, tx pgx.Tx, a CryptoAsset, eventSequence uint64, observedAt time.Time) error {
	return s.replaceCryptoAssetTx(ctx, tx, a, eventSequence, observedAt, false)
}

// ApplyCryptoAssetRolledBackTx restores the previous public crypto fact for a CBOM
// row after a migration rollback. Like migration completion, this is a projection of
// an immutable event rather than an imperative read-model mutation.
func (s *Store) ApplyCryptoAssetRolledBackTx(ctx context.Context, tx pgx.Tx, a CryptoAsset, eventSequence uint64, observedAt time.Time) error {
	return s.replaceCryptoAssetTx(ctx, tx, a, eventSequence, observedAt, true)
}

func (s *Store) replaceCryptoAssetTx(ctx context.Context, tx pgx.Tx, a CryptoAsset, eventSequence uint64, observedAt time.Time, restoreMissing bool) error {
	if err := validateCryptoAssetFingerprint(a); err != nil {
		return err
	}
	reasons := a.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	signature := a.Signature()
	sequence, err := cryptoAssetEventSequence(eventSequence)
	if err != nil {
		return err
	}
	var currentSequence int64
	err = tx.QueryRow(ctx,
		`SELECT event_sequence FROM crypto_assets WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		a.TenantID, a.ID).Scan(&currentSequence)
	if errors.Is(err, pgx.ErrNoRows) {
		if restoreMissing {
			return s.ApplyCryptoAssetObservedTx(ctx, tx, a, eventSequence, observedAt)
		}
		var desiredExists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM crypto_assets WHERE tenant_id = $1 AND signature = $2 AND is_active)`,
			a.TenantID, signature).Scan(&desiredExists); err != nil {
			return err
		}
		if desiredExists {
			// Compatibility with a row merged by an older binary: the compliant
			// fact remains even though that binary deleted the selected id.
			return nil
		}
		return pgx.ErrNoRows
	}
	if err != nil {
		return err
	}
	if sequence < currentSequence {
		return nil
	}
	// A scan can observe both a weak fact and the already-approved fact that a
	// migration will converge on (for example TLSv1 plus TLSv1.3 in one listener
	// directive). The unique tenant/signature index correctly prevents duplicate
	// read-model facts. On forward migration, retain the already-observed desired
	// fact and keep the obsolete weak selected row as an inactive, sequence-fenced
	// tombstone. Rollback reactivates that exact selected id from immutable event
	// evidence. Snapshots retain the tombstone; List hides it from operators.
	if !restoreMissing {
		var desiredExists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM crypto_assets
			                WHERE tenant_id = $1 AND signature = $2 AND id <> $3 AND is_active)`,
			a.TenantID, signature, a.ID).Scan(&desiredExists); err != nil {
			return err
		}
		if desiredExists {
			_, err := tx.Exec(ctx,
				`UPDATE crypto_assets SET is_active = false, event_sequence = $3
				  WHERE tenant_id = $1 AND id = $2`,
				a.TenantID, a.ID, sequence)
			return err
		}
	}
	tag, err := tx.Exec(ctx,
		`UPDATE crypto_assets
		    SET signature = $3, kind = $4, location = $5, algorithm = $6, key_bits = $7,
		        protocol = $8, cipher = $9, library = $10, strength = $11,
		        quantum_vulnerable = $12, out_of_policy = $13, reasons = $14,
		        event_sequence = $15, is_active = true, certificate_fingerprint = $16
		  WHERE tenant_id = $1 AND id = $2`,
		a.TenantID, a.ID, signature, a.Kind, a.Location, a.Algorithm, a.KeyBits,
		a.Protocol, a.Cipher, a.Library, a.Strength, a.QuantumVulnerable, a.OutOfPolicy, reasons, sequence, a.CertificateFingerprint)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if restoreMissing {
			return s.ApplyCryptoAssetObservedTx(ctx, tx, a, eventSequence, observedAt)
		}
		return pgx.ErrNoRows
	}
	return nil
}

func cryptoAssetEventSequence(sequence uint64) (int64, error) {
	if sequence > ^uint64(0)>>1 {
		return 0, fmt.Errorf("store: crypto asset event sequence %d exceeds PostgreSQL bigint", sequence)
	}
	return int64(sequence), nil
}

// ListCryptoAssets returns every crypto asset for the tenant, ordered.
func (s *Store) ListCryptoAssets(ctx context.Context, tenantID string) ([]CryptoAsset, error) {
	var out []CryptoAsset
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, kind, location, algorithm, key_bits, protocol, cipher,
			        library, strength, quantum_vulnerable, out_of_policy, reasons, created_at, certificate_fingerprint
			   FROM crypto_assets WHERE tenant_id = $1 AND is_active ORDER BY location, algorithm, protocol, cipher`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a CryptoAsset
			if err := rows.Scan(&a.ID, &a.TenantID, &a.Kind, &a.Location, &a.Algorithm, &a.KeyBits,
				&a.Protocol, &a.Cipher, &a.Library, &a.Strength, &a.QuantumVulnerable, &a.OutOfPolicy,
				&a.Reasons, &a.CreatedAt, &a.CertificateFingerprint); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// A missing fingerprint means unknown; it is never filled from a matching name.
func validateCryptoAssetFingerprint(a CryptoAsset) error {
	if a.CertificateFingerprint == "" {
		return nil
	}
	raw, err := hex.DecodeString(a.CertificateFingerprint)
	if err != nil || len(raw) != 32 || a.CertificateFingerprint != strings.ToLower(a.CertificateFingerprint) || a.Kind != "certificate-key" {
		return errors.New("store: observed certificate fingerprint requires a certificate-key finding and lowercase SHA-256")
	}
	return nil
}
