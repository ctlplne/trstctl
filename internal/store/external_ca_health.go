// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ExternalCAIssuance is one external CA's issuance evidence for a tenant (A161):
// certificates its issuance service recorded since a time, and the latest one.
type ExternalCAIssuance struct {
	IssuedSince  int
	LatestIssued *time.Time
}

// ExternalCAIssuanceStats reads the certificates an external CA issued for the
// tenant (source external-ca:<id>).
func (s *Store) ExternalCAIssuanceStats(ctx context.Context, tenantID, authorityID string, since time.Time) (ExternalCAIssuance, error) {
	var out ExternalCAIssuance
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FILTER (WHERE created_at >= $3), max(created_at)
			   FROM certificates WHERE tenant_id = $1 AND source = $2`,
			tenantID, "external-ca:"+authorityID, since.UTC()).Scan(&out.IssuedSince, &out.LatestIssued)
	})
	return out, err
}

// ExternalCAFailure is the latest enrollment diagnosis attributed to an
// external CA (its operation reference names the authority).
type ExternalCAFailure struct {
	Cause       string
	Summary     string
	Remediation string
	ObservedAt  time.Time
}

// LatestExternalCAFailure returns the most recent diagnosis whose latest
// observation came from the external CA, or false when none did. Diagnoses
// are kept per cause, so an older observation of a cause another authority
// hit since is not attributed here.
func (s *Store) LatestExternalCAFailure(ctx context.Context, tenantID, authorityID string) (ExternalCAFailure, bool, error) {
	var out ExternalCAFailure
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT cause, summary, remediation, observed_at FROM enrollment_diagnostics
			  WHERE tenant_id = $1 AND starts_with(operation_ref, $2)
			  ORDER BY observed_at DESC, event_sequence DESC LIMIT 1`,
			tenantID, "external-ca:"+authorityID+":").Scan(&out.Cause, &out.Summary, &out.Remediation, &out.ObservedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err == nil {
			found = true
		}
		return err
	})
	return out, found, err
}
