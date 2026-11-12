// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// CAUpstreamStandingApproval is a standing approval for one SPIRE server's
// upstream CA requests at one CA authority (OD-8): a ceremony granted it once,
// for the caller's principal, the SPIRE trust domain every signed CA must
// name, and the CA spec with its maximum lifetime, until it expires or is
// revoked. Every signing under it is counted.
type CAUpstreamStandingApproval struct {
	TenantID      string
	ID            string
	CAID          string
	Principal     string
	TrustDomain   string
	Spec          json.RawMessage
	MaxTTLSeconds int64
	CeremonyID    string
	GrantedBy     string
	GrantedAt     time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	RevokedBy     string
	RevokeReason  string
	Signings      int64
	LastSignedAt  *time.Time
	EventSequence uint64
}

// ErrCAUpstreamStandingApprovalNotFound reports an approval that is not there.
var ErrCAUpstreamStandingApprovalNotFound = errors.New("store: no such upstream standing approval")

// ApplyCAUpstreamStandingApprovalGrantedTx projects
// ca.upstream_standing_approval.granted; a replay converges.
func (s *Store) ApplyCAUpstreamStandingApprovalGrantedTx(ctx context.Context, tx pgx.Tx, a CAUpstreamStandingApproval) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO ca_upstream_standing_approvals (tenant_id, id, ca_id, principal, trust_domain, spec, max_ttl_seconds,
		                                             ceremony_id, granted_by, granted_at, expires_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
		a.TenantID, a.ID, a.CAID, a.Principal, a.TrustDomain, []byte(a.Spec), a.MaxTTLSeconds, a.CeremonyID,
		a.GrantedBy, a.GrantedAt, a.ExpiresAt,
		int64(a.EventSequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

// ApplyCAUpstreamStandingApprovalRevokedTx projects
// ca.upstream_standing_approval.revoked: the first revocation stands.
func (s *Store) ApplyCAUpstreamStandingApprovalRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, id, revokedBy, reason string, at time.Time, sequence uint64) error {
	_, err := tx.Exec(ctx,
		`UPDATE ca_upstream_standing_approvals
		    SET revoked_at = $3, revoked_by = $4, revoke_reason = $5, event_sequence = $6
		  WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL AND event_sequence < $6`,
		tenantID, id, at, revokedBy, reason,
		int64(sequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

// ApplyCAUpstreamStandingApprovalSignedTx counts one signing under an
// approval (ca.upstream_standing_approval.signed); replaying the same event
// counts nothing again.
func (s *Store) ApplyCAUpstreamStandingApprovalSignedTx(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time, sequence uint64) error {
	_, err := tx.Exec(ctx,
		`UPDATE ca_upstream_standing_approvals
		    SET signings = signings + 1, last_signed_at = $3, event_sequence = $4
		  WHERE tenant_id = $1 AND id = $2 AND event_sequence < $4`,
		tenantID, id, at,
		int64(sequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

const caUpstreamStandingApprovalColumns = `tenant_id::text, id::text, ca_id::text, principal, trust_domain, spec, max_ttl_seconds,
        ceremony_id, granted_by, granted_at, expires_at, revoked_at, revoked_by, revoke_reason, signings, last_signed_at,
        event_sequence`

func scanCAUpstreamStandingApproval(row pgx.Row, a *CAUpstreamStandingApproval) error {
	var seq int64
	var spec []byte
	if err := row.Scan(&a.TenantID, &a.ID, &a.CAID, &a.Principal, &a.TrustDomain, &spec, &a.MaxTTLSeconds,
		&a.CeremonyID, &a.GrantedBy, &a.GrantedAt, &a.ExpiresAt, &a.RevokedAt, &a.RevokedBy, &a.RevokeReason,
		&a.Signings, &a.LastSignedAt, &seq); err != nil {
		return err
	}
	a.Spec = json.RawMessage(spec)
	a.EventSequence = uint64(seq) // #nosec G115 -- non-negative by constraint (CWE-190)
	return nil
}

// ActiveCAUpstreamStandingApprovalTx is the newest unrevoked, unexpired
// approval at the authority for the principal, read in the signing
// transaction so a revocation committed first is seen.
func (s *Store) ActiveCAUpstreamStandingApprovalTx(ctx context.Context, tx pgx.Tx, tenantID, caID, principal string, now time.Time) (CAUpstreamStandingApproval, bool, error) {
	var a CAUpstreamStandingApproval
	err := scanCAUpstreamStandingApproval(tx.QueryRow(ctx,
		`SELECT `+caUpstreamStandingApprovalColumns+`
		   FROM ca_upstream_standing_approvals
		  WHERE tenant_id = $1 AND ca_id = $2 AND principal = $3 AND revoked_at IS NULL AND expires_at > $4
		  ORDER BY granted_at DESC, id
		  LIMIT 1
		  FOR SHARE`, tenantID, caID, principal, now), &a)
	if errors.Is(err, pgx.ErrNoRows) {
		return CAUpstreamStandingApproval{}, false, nil
	}
	return a, err == nil, err
}

// GetCAUpstreamStandingApproval reads one approval.
func (s *Store) GetCAUpstreamStandingApproval(ctx context.Context, tenantID, id string) (CAUpstreamStandingApproval, error) {
	var a CAUpstreamStandingApproval
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanCAUpstreamStandingApproval(tx.QueryRow(ctx,
			`SELECT `+caUpstreamStandingApprovalColumns+`
			   FROM ca_upstream_standing_approvals WHERE tenant_id = $1 AND id = $2`, tenantID, id), &a)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return CAUpstreamStandingApproval{}, ErrCAUpstreamStandingApprovalNotFound
	}
	return a, err
}

// ListCAUpstreamStandingApprovals lists an authority's approvals, newest
// first, at most 200.
func (s *Store) ListCAUpstreamStandingApprovals(ctx context.Context, tenantID, caID string) ([]CAUpstreamStandingApproval, error) {
	var out []CAUpstreamStandingApproval
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+caUpstreamStandingApprovalColumns+`
			   FROM ca_upstream_standing_approvals WHERE tenant_id = $1 AND ca_id = $2
			  ORDER BY granted_at DESC, id LIMIT 200`, tenantID, caID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a CAUpstreamStandingApproval
			if err := scanCAUpstreamStandingApproval(rows, &a); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
