// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// The revocation report (A245) reads, for one revoked certificate, the four
// places a revocation has to take hold: the CA's own record (what OCSP and the
// CRL answer from), the destinations it was delivered to, the endpoints that
// presented it, and the stops that end sessions already open. It writes
// nothing.

// RevocationCAEvidence is the built-in CA's record of the serial.
type RevocationCAEvidence struct {
	// Recorded reports a ca_issued_certs row for the serial; RevokedAt is set
	// once OCSP and the CRL treat it as revoked.
	Recorded  bool
	RevokedAt *time.Time
	// CRLNumber and CRLThisUpdate name the first CRL generated since the
	// revocation; zero when none has been.
	CRLNumber     int64
	CRLThisUpdate *time.Time
}

// RevocationDelivery is one destination the certificate was delivered to and
// what that destination received last.
type RevocationDelivery struct {
	Target          string
	DeliveredAt     time.Time
	LatestStatus    string
	LatestPrint     string
	LatestAt        time.Time
	LatestDetail    string
	LatestReceiptID string
}

// RevocationObservation is an endpoint's newest observation that bears on the
// certificate: it presented it, or was expected to.
type RevocationObservation struct {
	EndpointID          string
	Vantage             string
	Reached             bool
	Mismatch            string
	ObservedFingerprint string
	CheckedAt           time.Time
}

// RevocationStop is a signed host receipt that removed or stopped serving the
// certificate.
type RevocationStop struct {
	Target string
	Status string
	At     time.Time
}

// RevocationEvidence is everything the report reads for one certificate.
type RevocationEvidence struct {
	CA           RevocationCAEvidence
	Deliveries   []RevocationDelivery
	Observations []RevocationObservation
	Stops        []RevocationStop
}

// CertificateRevocationEvidence reads the evidence for one certificate of an
// identity. caID and serial name the built-in CA's record; caID is empty for
// a certificate another CA issued.
func (s *Store) CertificateRevocationEvidence(ctx context.Context, tenantID, identityID, caID, serial, fingerprint string, revokedAt time.Time) (RevocationEvidence, error) {
	var out RevocationEvidence
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if isUUIDText(caID) && serial != "" {
			err := tx.QueryRow(ctx, `SELECT revoked_at FROM ca_issued_certs WHERE tenant_id = $1 AND ca_id = $2::uuid AND serial = $3`,
				tenantID, caID, serial).Scan(&out.CA.RevokedAt)
			switch {
			case err == nil:
				out.CA.Recorded = true
			case err != pgx.ErrNoRows:
				return err
			}
			if out.CA.RevokedAt != nil {
				var at time.Time
				err := tx.QueryRow(ctx, `SELECT crl_number, this_update FROM ca_crls
					WHERE tenant_id = $1 AND ca_id = $2::uuid AND this_update >= $3
					ORDER BY crl_number ASC LIMIT 1`, tenantID, caID, *out.CA.RevokedAt).Scan(&out.CA.CRLNumber, &at)
				switch {
				case err == nil:
					out.CA.CRLThisUpdate = &at
				case err != pgx.ErrNoRows:
					return err
				}
			}
		}
		rows, err := tx.Query(ctx, `
			SELECT d.target, max(d.updated_at),
			       l.status, l.fingerprint, l.updated_at, l.detail, l.id::text
			  FROM connector_delivery_receipts d
			  CROSS JOIN LATERAL (
			        SELECT x.status, x.fingerprint, x.updated_at, x.detail, x.id
			          FROM connector_delivery_receipts x
			         WHERE x.tenant_id = d.tenant_id AND x.identity_id = d.identity_id AND x.target = d.target
			         ORDER BY x.updated_at DESC, x.id DESC LIMIT 1) l
			 WHERE d.tenant_id = $1 AND d.identity_id = $2::uuid AND d.fingerprint = $3
			   AND d.destination IN ('connector.deploy', 'endpoint.renew') AND d.status IN ('delivered', 'verified')
			 GROUP BY d.target, l.status, l.fingerprint, l.updated_at, l.detail, l.id
			 ORDER BY d.target LIMIT 100`, tenantID, identityID, fingerprint)
		if err != nil {
			return err
		}
		for rows.Next() {
			var d RevocationDelivery
			if err := rows.Scan(&d.Target, &d.DeliveredAt, &d.LatestStatus, &d.LatestPrint, &d.LatestAt, &d.LatestDetail, &d.LatestReceiptID); err != nil {
				rows.Close()
				return err
			}
			out.Deliveries = append(out.Deliveries, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `
			SELECT endpoint_id, vantage, reached, mismatch, observed_fingerprint, last_checked_at
			  FROM endpoint_verifications
			 WHERE tenant_id = $1 AND (observed_fingerprint = $2 OR expected_fingerprint = $2)
			 ORDER BY endpoint_id, vantage LIMIT 100`, tenantID, fingerprint)
		if err != nil {
			return err
		}
		for rows.Next() {
			var o RevocationObservation
			if err := rows.Scan(&o.EndpointID, &o.Vantage, &o.Reached, &o.Mismatch, &o.ObservedFingerprint, &o.CheckedAt); err != nil {
				rows.Close()
				return err
			}
			out.Observations = append(out.Observations, o)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `
			SELECT target, status, updated_at FROM connector_delivery_receipts
			 WHERE tenant_id = $1 AND identity_id = $2::uuid AND fingerprint = $3 AND updated_at >= $4
			   AND status IN ('containment_stopped', 'purged', 'taken_down')
			 ORDER BY updated_at DESC LIMIT 100`, tenantID, identityID, fingerprint, revokedAt)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var st RevocationStop
			if err := rows.Scan(&st.Target, &st.Status, &st.At); err != nil {
				return err
			}
			out.Stops = append(out.Stops, st)
		}
		return rows.Err()
	})
	return out, err
}

// isUUIDText reports whether s is a canonical UUID string.
func isUUIDText(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
		default:
			return false
		}
	}
	return true
}

// IdentityRevokedCertificates lists an identity's revoked certificates, bound
// by the same exact issuance or delivery evidence the revoke command follows,
// newest revocation first.
func (s *Store) IdentityRevokedCertificates(ctx context.Context, tenantID, identityID string, limit int) ([]Certificate, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var out []Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+certificateColumns+` FROM certificates
   WHERE tenant_id=$1 AND status = 'revoked' AND `+identityRevocationBinding+`
   ORDER BY revoked_at DESC NULLS LAST, id LIMIT $3`, tenantID, identityID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Certificate
			if err := scanCertificate(rows, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
