// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ScannedIssuer is one issuer certificate a scan saw served with a leaf (A211).
type ScannedIssuer struct {
	Position       int
	CertificateDER []byte
	SHA256         string
}

// ApplyScannedCertificateChainTx replaces a leaf's kept issuers with a newer
// observation; an older or replayed one changes nothing.
func (s *Store) ApplyScannedCertificateChainTx(ctx context.Context, tx pgx.Tx, tenantID, leafFingerprint string,
	issuers []ScannedIssuer, observedAt time.Time, sequence uint64) error {
	seq := int64(sequence) // #nosec G115 -- event sequences fit int64 (CWE-190)
	var newest int64
	if err := tx.QueryRow(ctx,
		`SELECT coalesce(max(event_sequence), 0) FROM scanned_certificate_chains
		  WHERE tenant_id = $1 AND leaf_fingerprint = $2`, tenantID, leafFingerprint).Scan(&newest); err != nil {
		return err
	}
	if newest >= seq {
		return nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM scanned_certificate_chains WHERE tenant_id = $1 AND leaf_fingerprint = $2`,
		tenantID, leafFingerprint); err != nil {
		return err
	}
	for _, issuer := range issuers {
		if _, err := tx.Exec(ctx,
			`INSERT INTO scanned_certificate_chains (tenant_id, leaf_fingerprint, position, certificate_der,
			        certificate_sha256, observed_at, event_sequence)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			tenantID, leafFingerprint, issuer.Position, issuer.CertificateDER, issuer.SHA256, observedAt, seq); err != nil {
			return err
		}
	}
	return nil
}

// ScannedCertificateChains returns the kept issuers of each leaf, in served
// order.
func (s *Store) ScannedCertificateChains(ctx context.Context, tenantID string, leafFingerprints []string) (map[string][]ScannedIssuer, error) {
	out := map[string][]ScannedIssuer{}
	if len(leafFingerprints) == 0 {
		return out, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT leaf_fingerprint, position, certificate_der, certificate_sha256 FROM scanned_certificate_chains
			  WHERE tenant_id = $1 AND leaf_fingerprint = ANY($2::text[]) ORDER BY leaf_fingerprint, position`,
			tenantID, leafFingerprints)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var leaf string
			var issuer ScannedIssuer
			if err := rows.Scan(&leaf, &issuer.Position, &issuer.CertificateDER, &issuer.SHA256); err != nil {
				return err
			}
			out[leaf] = append(out[leaf], issuer)
		}
		return rows.Err()
	})
	return out, err
}
