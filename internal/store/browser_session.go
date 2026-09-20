// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// BrowserSession is the pseudonymous operational record shared by browser-auth
// replicas. SessionHash and SubjectHash are one-way SHA-256 digests; raw session
// IDs, names, email addresses, and role claims are never stored in this table.
type BrowserSession struct {
	TenantID    string
	SessionHash string
	SubjectHash string
	ExpiresAt   time.Time
	CreatedAt   time.Time
	LastSeenAt  time.Time
	RevokedAt   *time.Time
}

// CreateBrowserSession records a newly issued session and removes already-expired
// rows for the same tenant. Both statements execute under the tenant's RLS scope.
func (s *Store) CreateBrowserSession(ctx context.Context, session BrowserSession) error {
	return s.WithTenant(ctx, session.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM browser_sessions WHERE tenant_id = $1 AND expires_at <= $2`,
			session.TenantID, session.CreatedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO browser_sessions
			        (tenant_id, session_hash, subject_hash, expires_at, created_at, last_seen_at, revoked_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			session.TenantID, session.SessionHash, session.SubjectHash, session.ExpiresAt,
			session.CreatedAt, session.LastSeenAt, session.RevokedAt)
		return err
	})
}

// GetBrowserSession returns one exact tenant-scoped session record.
func (s *Store) GetBrowserSession(ctx context.Context, tenantID, sessionHash string) (BrowserSession, error) {
	var session BrowserSession
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id::text, session_hash, subject_hash, expires_at, created_at, last_seen_at, revoked_at
			   FROM browser_sessions
			  WHERE tenant_id = $1 AND session_hash = $2`,
			tenantID, sessionHash).Scan(
			&session.TenantID, &session.SessionHash, &session.SubjectHash, &session.ExpiresAt,
			&session.CreatedAt, &session.LastSeenAt, &session.RevokedAt)
	})
	return session, err
}

// TouchBrowserSession advances the idle-time authority for one exact session.
func (s *Store) TouchBrowserSession(ctx context.Context, tenantID, sessionHash string, seenAt time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE browser_sessions
			    SET last_seen_at = $3
			  WHERE tenant_id = $1 AND session_hash = $2`,
			tenantID, sessionHash, seenAt)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
}

// RevokeBrowserSession invalidates one session and remains idempotent for an
// already-revoked row. Missing rows are reported so callers can distinguish them.
func (s *Store) RevokeBrowserSession(ctx context.Context, tenantID, sessionHash string, revokedAt time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE browser_sessions
			    SET revoked_at = coalesce(revoked_at, $3)
			  WHERE tenant_id = $1 AND session_hash = $2`,
			tenantID, sessionHash, revokedAt)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
}

// RevokeBrowserSessionsBySubject invalidates every live session for one
// pseudonymous subject inside one tenant. It never scans another tenant.
func (s *Store) RevokeBrowserSessionsBySubject(ctx context.Context, tenantID, subjectHash string, revokedAt time.Time) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE browser_sessions
			    SET revoked_at = coalesce(revoked_at, $3)
			  WHERE tenant_id = $1 AND subject_hash = $2`,
			tenantID, subjectHash, revokedAt)
		return err
	})
}
