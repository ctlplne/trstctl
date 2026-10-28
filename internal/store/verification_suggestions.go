// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
)

// VerificationAddressEvidence is one discovery finding that saw, at an
// address, a leaf trstctl delivered to a target (A214).
type VerificationAddressEvidence struct {
	FindingID    string
	RunID        string
	SourceID     string
	Fingerprint  string
	DiscoveredAt time.Time
}

// VerificationAddressSuggestion is an address where discovery saw a leaf
// trstctl delivered to the target, with the findings that saw it.
type VerificationAddressSuggestion struct {
	Address  string
	LastSeen time.Time
	Evidence []VerificationAddressEvidence
}

// Bounds for a target's suggestions.
const (
	maxVerificationSuggestions        = 20
	maxVerificationSuggestionEvidence = 5
	verificationSuggestionScanLimit   = 500
)

// VerificationAddressSuggestions lists where discovery saw the leaves trstctl
// delivered to one target (by its connector and name, as delivery receipts
// record it): TLS findings whose fingerprint is a leaf delivered there and not
// purged since, at a host:port address, newest first and bounded. Nothing is
// resolved or guessed; an address with no such finding is not suggested.
func (s *Store) VerificationAddressSuggestions(ctx context.Context, tenantID, connectorName, targetName string) ([]VerificationAddressSuggestion, error) {
	var out []VerificationAddressSuggestion
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`WITH delivered AS (
			     SELECT DISTINCT lower(d.fingerprint) AS fingerprint
			       FROM connector_delivery_receipts d
			      WHERE d.tenant_id = $1 AND d.connector = $2 AND d.target = $3 AND d.fingerprint <> ''
			        AND ((d.destination = 'connector.deploy' AND d.status IN ('delivered', 'verified'))
			          OR (d.destination = 'connector.rollback' AND d.status = 'rolled_back'))
			        AND NOT EXISTS (
			          SELECT 1 FROM connector_delivery_receipts p
			           WHERE p.tenant_id = d.tenant_id AND lower(p.fingerprint) = lower(d.fingerprint)
			             AND p.connector = d.connector AND p.target = d.target
			             AND p.destination = 'endpoint.purge' AND p.status = 'purged'
			             AND p.updated_at >= d.updated_at)
			 )
			 SELECT f.id::text, f.run_id::text, f.source_id::text, f.ref, f.fingerprint, f.discovered_at
			   FROM discovery_findings f
			  WHERE f.tenant_id = $1 AND f.kind = 'x509_certificate'
			    AND f.fingerprint IN (SELECT fingerprint FROM delivered)
			  ORDER BY f.discovered_at DESC, f.id
			  LIMIT $4`, tenantID, connectorName, targetName, verificationSuggestionScanLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		index := map[string]int{}
		for rows.Next() {
			var ref string
			var e VerificationAddressEvidence
			if err := rows.Scan(&e.FindingID, &e.RunID, &e.SourceID, &ref, &e.Fingerprint, &e.DiscoveredAt); err != nil {
				return err
			}
			if _, _, err := net.SplitHostPort(ref); err != nil {
				continue
			}
			i, seen := index[ref]
			if !seen {
				if len(out) >= maxVerificationSuggestions {
					continue
				}
				i = len(out)
				index[ref] = i
				out = append(out, VerificationAddressSuggestion{Address: ref, LastSeen: e.DiscoveredAt})
			}
			if len(out[i].Evidence) < maxVerificationSuggestionEvidence {
				out[i].Evidence = append(out[i].Evidence, e)
			}
		}
		return rows.Err()
	})
	return out, err
}
