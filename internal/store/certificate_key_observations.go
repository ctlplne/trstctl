// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// MaxCertificateKeyObservations bounds one certificate's key observations.
const MaxCertificateKeyObservations = 20

// CertificateKeyObservation is one private-key file a host agent's inventory
// reported whose public key (SPKI SHA-256) matches a certificate (A121). It is
// the agent's metadata-only report of where a matching key sits, never a
// custody record: the agent saw a file, not how the key was made.
type CertificateKeyObservation struct {
	Agent       string
	Path        string
	Metadata    []byte
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

// ListCertificateKeyObservations returns the newest private-key observations
// whose public-key fingerprint is spkiSHA256, from agent inventory sources only.
func (s *Store) ListCertificateKeyObservations(ctx context.Context, tenantID, spkiSHA256 string) ([]CertificateKeyObservation, error) {
	var out []CertificateKeyObservation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT COALESCE(s.config->>'agent', ''), f.ref, f.metadata, f.first_seen_at, f.last_seen_at
			   FROM discovery_findings f
			   JOIN discovery_sources s ON s.tenant_id = f.tenant_id AND s.id = f.source_id
			  WHERE f.tenant_id = $1 AND f.kind = 'private_key' AND f.fingerprint = $2 AND s.kind = 'agent'
			  ORDER BY f.last_seen_at DESC, f.ref
			  LIMIT $3`, tenantID, spkiSHA256, MaxCertificateKeyObservations)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o CertificateKeyObservation
			if err := rows.Scan(&o.Agent, &o.Path, &o.Metadata, &o.FirstSeenAt, &o.LastSeenAt); err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}
