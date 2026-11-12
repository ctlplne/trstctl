// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Reads for the CycloneDX CBOM export (Q3-L2): the certificates the
// certificate inventory holds for the CBOM's certificate keys, and the newest
// finding of each ref that host agents and observers reported.

// MaxCBOMExportFindingsPerKind bounds one kind's findings in one export.
const MaxCBOMExportFindingsPerKind = 10000

// maxCertificatesByFingerprint bounds one batch lookup.
const maxCertificatesByFingerprint = 50000

// CertificatesByFingerprints returns the inventory's certificates with any of
// fingerprints, keyed by fingerprint. Tenant-scoped (RLS and predicate).
func (s *Store) CertificatesByFingerprints(ctx context.Context, tenantID string, fingerprints []string) (map[string]Certificate, error) {
	out := map[string]Certificate{}
	if len(fingerprints) == 0 {
		return out, nil
	}
	if len(fingerprints) > maxCertificatesByFingerprint {
		return nil, fmt.Errorf("store: %d fingerprints in one lookup; at most %d", len(fingerprints), maxCertificatesByFingerprint)
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+certificateColumns+`
			   FROM certificates WHERE tenant_id = $1 AND fingerprint = ANY($2::text[])`, tenantID, fingerprints)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Certificate
			if err := scanCertificate(rows, &c); err != nil {
				return err
			}
			out[c.Fingerprint] = c
		}
		return rows.Err()
	})
	return out, err
}

// LatestDiscoveryFindingsOfKind returns the most recently seen finding of each
// ref of kind, ordered by ref, at most limit of them; more reports that refs
// were left out at the bound.
func (s *Store) LatestDiscoveryFindingsOfKind(ctx context.Context, tenantID, kind string, limit int) (out []DiscoveryFinding, more bool, err error) {
	if kind == "" || limit < 1 || limit > MaxCBOMExportFindingsPerKind {
		return nil, false, fmt.Errorf("store: latest findings of kind %q with limit %d", kind, limit)
	}
	err = s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (f.ref)
		              f.id::text, f.tenant_id::text, f.run_id::text, f.source_id::text, f.kind, f.ref,
		              f.provenance, f.fingerprint, f.risk_score, f.metadata, f.discovered_at,
		              f.triage_status, f.managed_identity_id::text, f.triage_actor, f.triage_reason, f.triaged_at,
		              f.first_seen_at, f.last_seen_at, f.seen_count,
		              f.triage_assignee, f.triage_due_at, f.triage_evidence_ref, f.risk_accepted_until
		         FROM discovery_findings f
		        WHERE f.tenant_id = $1 AND f.kind = $2
		        ORDER BY f.ref, f.last_seen_at DESC, f.id DESC
		        LIMIT $3`, tenantID, kind, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f DiscoveryFinding
			if err := scanDiscoveryFinding(rows, &f); err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}
