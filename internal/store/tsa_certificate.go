// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// TSACertificate is one projected timestamping-authority certificate (A145).
type TSACertificate struct {
	TenantID      string     `json:"tenant_id"`
	Serial        string     `json:"serial"`
	CAID          string     `json:"ca_id"`
	Handle        string     `json:"handle"`
	CertDER       []byte     `json:"cert_der"`
	CertSHA256    string     `json:"cert_sha256"`
	NotBefore     time.Time  `json:"not_before"`
	NotAfter      time.Time  `json:"not_after"`
	RegisteredAt  time.Time  `json:"registered_at"`
	EventSequence uint64     `json:"event_sequence"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	ReasonCode    *int       `json:"reason_code,omitempty"`
}

// ApplyTSACertificateRegisteredTx records a TSA certificate; replaying the
// event is a no-op.
func (s *Store) ApplyTSACertificateRegisteredTx(ctx context.Context, tx pgx.Tx, c TSACertificate) error {
	if c.TenantID == "" || c.Serial == "" || c.CAID == "" || c.Handle == "" || len(c.CertDER) == 0 || c.EventSequence == 0 {
		return errors.New("store: TSA certificate registration is incomplete")
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO tsa_certificates (tenant_id, serial, ca_id, handle, cert_der, cert_sha256, not_before, not_after,
		                               registered_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (tenant_id, serial) DO NOTHING`,
		c.TenantID, c.Serial, c.CAID, c.Handle, c.CertDER, c.CertSHA256, c.NotBefore.UTC(), c.NotAfter.UTC(),
		c.RegisteredAt.UTC(), int64(c.EventSequence)) // #nosec G115 -- event-log sequence fits a Postgres bigint (CWE-190)
	return err
}

// ApplyTSACertificateRevokedTx marks a TSA certificate revoked, keeping the
// first revocation on a replay.
func (s *Store) ApplyTSACertificateRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, serial string, reasonCode int, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE tsa_certificates SET revoked_at = $3, reason_code = $4
		  WHERE tenant_id = $1 AND serial = $2 AND revoked_at IS NULL`,
		tenantID, serial, at.UTC(), reasonCode)
	return err
}

// ListTSACertificates returns a tenant's TSA certificates, newest first.
func (s *Store) ListTSACertificates(ctx context.Context, tenantID string) ([]TSACertificate, error) {
	var out []TSACertificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, serial, ca_id, handle, cert_der, cert_sha256, not_before, not_after,
			        registered_at, event_sequence, revoked_at, reason_code
			   FROM tsa_certificates WHERE tenant_id = $1 ORDER BY event_sequence DESC`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				c   TSACertificate
				seq int64
			)
			if err := rows.Scan(&c.TenantID, &c.Serial, &c.CAID, &c.Handle, &c.CertDER, &c.CertSHA256, &c.NotBefore,
				&c.NotAfter, &c.RegisteredAt, &seq, &c.RevokedAt, &c.ReasonCode); err != nil {
				return err
			}
			c.EventSequence = uint64(seq) // #nosec G115 -- the table CHECK keeps it positive (CWE-190)
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
