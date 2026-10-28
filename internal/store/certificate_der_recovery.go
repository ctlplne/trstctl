// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// CertificateDERRecovery is how an inventory row that held no certificate
// bytes got them (A215).
type CertificateDERRecovery struct {
	TenantID      string
	Fingerprint   string
	Method        string
	Evidence      string
	RecoveredAt   time.Time
	EventSequence uint64
}

// Where recovered certificate bytes came from.
const (
	// DERRecoveredFromCALedger: a mint of the tenant's own CA that retained
	// the certificate.
	DERRecoveredFromCALedger = "ca_ledger"
	// DERRecoveredFromEndpoint: the certificate the row's endpoint served.
	DERRecoveredFromEndpoint = "endpoint"
)

// ApplyCertificateDERRecoveredTx fills a row's empty certificate bytes with
// bytes the caller checked hash to its fingerprint, and keeps how they were
// found. A row that already holds bytes keeps them and records nothing, so a
// replay or a late recovery never replaces what another path recorded.
func (s *Store) ApplyCertificateDERRecoveredTx(ctx context.Context, tx pgx.Tx, r CertificateDERRecovery, der, pem []byte) error {
	tag, err := tx.Exec(ctx,
		`UPDATE certificates
		    SET certificate_der = $3,
		        certificate_pem = CASE WHEN octet_length(certificate_pem) = 0 THEN $4 ELSE certificate_pem END
		  WHERE tenant_id = $1 AND fingerprint = $2 AND octet_length(certificate_der) = 0`,
		r.TenantID, r.Fingerprint, der, pem)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO certificate_der_recoveries (tenant_id, fingerprint, method, evidence, recovered_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (tenant_id, fingerprint) DO UPDATE
		    SET method = EXCLUDED.method, evidence = EXCLUDED.evidence, recovered_at = EXCLUDED.recovered_at,
		        event_sequence = EXCLUDED.event_sequence
		  WHERE certificate_der_recoveries.event_sequence < EXCLUDED.event_sequence`,
		r.TenantID, r.Fingerprint, r.Method, r.Evidence, r.RecoveredAt,
		int64(r.EventSequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

// CertificateDERRecoveryFor reads how a certificate's bytes were recovered,
// if they were.
func (s *Store) CertificateDERRecoveryFor(ctx context.Context, tenantID, fingerprint string) (CertificateDERRecovery, bool, error) {
	var r CertificateDERRecovery
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var seq int64
		err := tx.QueryRow(ctx,
			`SELECT tenant_id::text, fingerprint, method, evidence, recovered_at, event_sequence
			   FROM certificate_der_recoveries WHERE tenant_id = $1 AND fingerprint = $2`, tenantID, fingerprint).
			Scan(&r.TenantID, &r.Fingerprint, &r.Method, &r.Evidence, &r.RecoveredAt, &seq)
		r.EventSequence = uint64(seq) // #nosec G115 -- positive by constraint (CWE-190)
		return err
	})
	if IsNotFound(err) {
		return CertificateDERRecovery{}, false, nil
	}
	return r, err == nil, err
}
