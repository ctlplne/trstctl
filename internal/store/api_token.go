// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/privacy"
)

// DelegatedTokenMinterMatches finds every authenticated minter in a retained
// token's chain, including revoked tokens. Old approval requests did not store
// the token ID, so any cross-subject token for that requester must fence its
// minter from acting as an independent reviewer. An old delegated token with
// no recorded minter makes every proposed reviewer conflict: the old request
// must be reopened under an independently identifiable requester. Subject
// references survive privacy erasure; every lookup is tenant-scoped.
func (s *Store) DelegatedTokenMinterMatches(ctx context.Context, tenantID, requester string, reviewers []string) (bool, error) {
	var matched bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		matched, err = s.DelegatedTokenMinterMatchesTx(ctx, tx, tenantID, requester, reviewers)
		return err
	})
	return matched, err
}

// DelegatedTokenMinterMatchesTx is the transaction-local form for approval
// recorders that already hold the request row lock.
func (s *Store) DelegatedTokenMinterMatchesTx(ctx context.Context, tx pgx.Tx, tenantID, requester string, reviewers []string) (bool, error) {
	if requester == "" || len(reviewers) == 0 {
		return false, nil
	}
	for _, reviewer := range reviewers {
		if authz.SameApprovalPrincipal(requester, reviewer) {
			return true, nil
		}
	}
	requesterRef := privacy.SubjectRef(tenantID, requester)
	ownerRef := requesterRef
	if owner, ok := authz.BundleRunPrincipal(requester); ok {
		ownerRef = privacy.SubjectRef(tenantID, owner)
	}
	var unknownMinter bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
	    SELECT 1 FROM api_tokens
	     WHERE tenant_id=$1 AND subject_ref IN ($2,$3) AND delegated AND btrim(minted_by_ref)=''
	)`, tenantID, requesterRef, ownerRef).Scan(&unknownMinter); err != nil {
		return false, fmt.Errorf("store: read historical delegated token provenance: %w", err)
	}
	if unknownMinter {
		return true, nil
	}
	rows, err := tx.Query(ctx, `WITH RECURSIVE minter_lineage(ref, name) AS (
	    SELECT minted_by_ref, minted_by FROM api_tokens
	     WHERE tenant_id=$1 AND subject_ref IN ($2,$3) AND minted_by_ref<>'' AND minted_by_ref<>subject_ref
	    UNION
	    SELECT t.minted_by_ref, t.minted_by FROM api_tokens AS t JOIN minter_lineage AS m ON t.subject_ref=m.ref
	     WHERE t.tenant_id=$1 AND t.minted_by_ref<>'' AND t.minted_by_ref<>t.subject_ref
	) SELECT ref, name FROM minter_lineage LIMIT 1025`, tenantID, requesterRef, ownerRef)
	if err != nil {
		return false, fmt.Errorf("store: read delegated token lineage: %w", err)
	}
	type minterIdentity struct{ ref, name string }
	minters := make([]minterIdentity, 0)
	for rows.Next() {
		var minter minterIdentity
		if err := rows.Scan(&minter.ref, &minter.name); err != nil {
			rows.Close()
			return false, err
		}
		minters = append(minters, minter)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()
	if len(minters) > 1024 {
		return false, fmt.Errorf("store: delegated token lineage exceeds review bound")
	}
	if len(minters) == 0 {
		return false, nil
	}
	identifiers := make([]string, 0, 3*len(reviewers))
	for _, reviewer := range reviewers {
		if owner, ok := authz.BundleRunPrincipal(reviewer); ok {
			reviewer = owner
		}
		if reviewer == "" {
			continue
		}
		identifiers = append(identifiers, reviewer)
		var email, displayName string
		err := tx.QueryRow(ctx, `SELECT email, display_name FROM tenant_members WHERE tenant_id=$1 AND subject_ref=$2`,
			tenantID, privacy.SubjectRef(tenantID, reviewer)).Scan(&email, &displayName)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return false, fmt.Errorf("store: read reviewer member identifiers: %w", err)
		}
		if err == nil {
			identifiers = append(identifiers, email, displayName)
		}
	}
	for _, minter := range minters {
		for _, identifier := range identifiers {
			identifier = strings.TrimSpace(identifier)
			if identifier != "" && (privacy.SubjectRef(tenantID, identifier) == minter.ref || strings.EqualFold(identifier, minter.name)) {
				return true, nil
			}
		}
	}
	return false, nil
}

// APITokenRecord is a stored API token: its identity, scopes, and expiry, plus
// the hash of its secret. The secret itself is never stored.
type APITokenRecord struct {
	ID               string
	TenantID         string
	TokenHash        string
	Subject          string
	MintedBy         string
	Scopes           []string
	ExpiresAt        *time.Time
	CreatedAt        time.Time
	RevokedAt        *time.Time
	RevokedBy        string
	RevocationReason string
	// Delegated is true when someone other than Subject minted the token through
	// the served API (F262). Rows projected before migration 0231, and rows
	// seeded outside the event log, read as false.
	Delegated bool
	// EventSequence orders this bearer against a durable subject offboard fence.
	// It is populated by the projector and is not secret material.
	EventSequence uint64
}

// CreateAPIToken inserts a token in its tenant context (RLS-enforced), with a
// server-generated id. The caller supplies the precomputed token hash.
func (s *Store) CreateAPIToken(ctx context.Context, r APITokenRecord) (APITokenRecord, error) {
	scopes := r.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	minterRef := ""
	if r.MintedBy != "" {
		minterRef = privacy.SubjectRef(r.TenantID, r.MintedBy)
	}
	err := s.WithTenant(ctx, r.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO api_tokens (id, tenant_id, token_hash, subject, subject_ref, scopes, expires_at, minted_by, minted_by_ref)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8)
			 RETURNING id::text, created_at`,
			r.TenantID, r.TokenHash, r.Subject, privacy.SubjectRef(r.TenantID, r.Subject), scopes, r.ExpiresAt, r.MintedBy, minterRef).Scan(&r.ID, &r.CreatedAt)
	})
	return r, err
}

// ApplyAPITokenCreatedTx projects an api_token.created event into the token read
// model. The token secret itself is never in this row or the event; only its
// lookup hash is stored.
func (s *Store) ApplyAPITokenCreatedTx(ctx context.Context, tx pgx.Tx, r APITokenRecord) error {
	if r.EventSequence > 1<<63-1 {
		return errors.New("store: API-token source sequence exceeds PostgreSQL bigint")
	}
	scopes := r.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	minterRef := ""
	if r.MintedBy != "" {
		minterRef = privacy.SubjectRef(r.TenantID, r.MintedBy)
	}
	if err := lockUpsertArbiterTx(ctx, tx, "api_tokens", r.TenantID, r.ID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO api_tokens (id, tenant_id, token_hash, subject, subject_ref, scopes, expires_at, created_at, delegated, minted_by, minted_by_ref, revoked_at)
		 VALUES ($1, $2, $3,
		   CASE WHEN EXISTS (SELECT 1 FROM privacy_subject_erasures AS e
		                     WHERE e.tenant_id = $2 AND e.subject_ref = $5::char(64))
		        THEN 'erased:' || left($5, 12) ELSE $4 END,
		   $5::char(64), $6, $7, $8::timestamptz, $9,
		   CASE WHEN EXISTS (SELECT 1 FROM privacy_subject_erasures AS e
		                     WHERE e.tenant_id = $2 AND e.subject_ref = $12::char(64))
		        THEN 'erased:' || left($12, 12) ELSE $11 END, $12::char(64),
		   CASE WHEN EXISTS (SELECT 1 FROM privacy_subject_erasures AS e
		                     WHERE e.tenant_id = $2 AND e.subject_ref IN ($5::char(64), $12::char(64)))
		          OR EXISTS (SELECT 1 FROM tenant_member_offboard_commands AS c
		                     WHERE c.tenant_id = $2 AND c.subject_ref IN ($5::char(64), $12::char(64))
		                       AND c.last_event_sequence >= $10::bigint) THEN $8::timestamptz ELSE NULL END)
		 ON CONFLICT (id) DO UPDATE
		    SET token_hash = EXCLUDED.token_hash,
		        subject = EXCLUDED.subject,
		        subject_ref = EXCLUDED.subject_ref,
		        scopes = EXCLUDED.scopes,
		        expires_at = EXCLUDED.expires_at,
		        created_at = EXCLUDED.created_at,
		        delegated = EXCLUDED.delegated,
		        minted_by = EXCLUDED.minted_by,
		        minted_by_ref = EXCLUDED.minted_by_ref,
		        revoked_at = COALESCE(api_tokens.revoked_at, EXCLUDED.revoked_at)`,
		r.ID, r.TenantID, r.TokenHash, r.Subject, privacy.SubjectRef(r.TenantID, r.Subject), scopes, r.ExpiresAt, r.CreatedAt, r.Delegated, strconv.FormatUint(r.EventSequence, 10), r.MintedBy, minterRef)
	return err
}

// ApplyAPITokenRevokedTx projects an api_token.revoked event. Replaying it is
// idempotent: the first revocation timestamp wins.
func (s *Store) ApplyAPITokenRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, id, revokedBy, reason string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE api_tokens
		    SET revoked_at = COALESCE(revoked_at, $3),
		        revoked_by = CASE WHEN revoked_by = '' THEN $4 ELSE revoked_by END,
		        revocation_reason = CASE WHEN revocation_reason = '' THEN $5 ELSE revocation_reason END
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, at, revokedBy, reason)
	return err
}

// ApplyAPITokensRevokedForSubjectTx projects member offboarding by revoking
// tokens owned or minted by the departing subject.
func (s *Store) ApplyAPITokensRevokedForSubjectTx(ctx context.Context, tx pgx.Tx, tenantID, subject, revokedBy, reason string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE api_tokens
		    SET revoked_at = COALESCE(revoked_at, $3),
		        revoked_by = CASE WHEN revoked_by = '' THEN $4 ELSE revoked_by END,
		        revocation_reason = CASE WHEN revocation_reason = '' THEN $5 ELSE revocation_reason END
		  WHERE tenant_id = $1 AND (subject_ref = $2 OR minted_by_ref = $2) AND revoked_at IS NULL`,
		tenantID, privacy.SubjectRef(tenantID, subject), at, revokedBy, reason)
	return err
}

// GetAPIToken loads one token row in its tenant context.
func (s *Store) GetAPIToken(ctx context.Context, tenantID, id string) (APITokenRecord, error) {
	var r APITokenRecord
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, token_hash, subject, scopes, expires_at, created_at,
			        revoked_at, revoked_by, revocation_reason, minted_by
			   FROM api_tokens WHERE tenant_id = $1 AND id = $2`,
			tenantID, id).Scan(&r.ID, &r.TenantID, &r.TokenHash, &r.Subject, &r.Scopes, &r.ExpiresAt, &r.CreatedAt, &r.RevokedAt, &r.RevokedBy, &r.RevocationReason, &r.MintedBy)
	})
	return r, err
}

// CountActiveAPITokensForSubject returns how many bearer credentials offboarding
// will revoke for a subject as either holder or minter.
func (s *Store) CountActiveAPITokensForSubject(ctx context.Context, tenantID, subject string) (int, error) {
	var n int
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM api_tokens WHERE tenant_id = $1 AND (subject_ref = $2 OR minted_by_ref = $2) AND revoked_at IS NULL`,
			tenantID, privacy.SubjectRef(tenantID, subject)).Scan(&n)
	})
	return n, err
}

// ListAPITokensPage returns a tenant-scoped page of token metadata. It never
// returns token secrets.
func (s *Store) ListAPITokensPage(ctx context.Context, tenantID, afterID, subject string, includeRevoked bool, limit int) ([]APITokenRecord, error) {
	var out []APITokenRecord
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, token_hash, subject, scopes, expires_at, created_at,
			        revoked_at, revoked_by, revocation_reason, minted_by
			   FROM api_tokens
			  WHERE tenant_id = $1
			    AND id > $2
			    AND ($3 = '' OR subject = $3)
			    AND ($4 OR revoked_at IS NULL)
			  ORDER BY api_tokens.id LIMIT $5`,
			tenantID, afterID, subject, includeRevoked, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r APITokenRecord
			if err := rows.Scan(&r.ID, &r.TenantID, &r.TokenHash, &r.Subject, &r.Scopes, &r.ExpiresAt, &r.CreatedAt, &r.RevokedAt, &r.RevokedBy, &r.RevocationReason, &r.MintedBy); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ListExpiredAPITokens returns active API tokens whose server-side expiry has
// passed. Leaseworker runs before a request tenant is known, so this is a bounded
// system sweep that returns each row's owning tenant for event-sourced revocation.
func (s *Store) ListExpiredAPITokens(ctx context.Context, now time.Time, limit int) ([]APITokenRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — leaseworker sweeps expired API tokens across tenants before any request tenant exists; it returns tenant_id and then revokes through tenant-scoped event commands. Cross-tenant by design; bounded by LIMIT and carries no raw token material (AN-1 exemption).
		`SELECT id::text, tenant_id::text, token_hash, subject, scopes, expires_at, created_at,
		        revoked_at, revoked_by, revocation_reason, minted_by
		   FROM api_tokens
		  WHERE expires_at IS NOT NULL
		    AND expires_at <= $1
		    AND revoked_at IS NULL
		  ORDER BY expires_at, id
		  LIMIT $2`,
		now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APITokenRecord
	for rows.Next() {
		var r APITokenRecord
		if err := rows.Scan(&r.ID, &r.TenantID, &r.TokenHash, &r.Subject, &r.Scopes, &r.ExpiresAt, &r.CreatedAt, &r.RevokedAt, &r.RevokedBy, &r.RevocationReason, &r.MintedBy); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LookupAPITokenByHash finds a token by its hash. Authentication runs before any
// tenant context is known, so this is a system operation (the token's hash is a
// globally unique, high-entropy secret); it returns the token's tenant. It
// returns pgx.ErrNoRows (see IsNotFound) when no such token exists.
func (s *Store) LookupAPITokenByHash(ctx context.Context, hash string) (APITokenRecord, error) {
	var r APITokenRecord
	err := s.pool.QueryRow(ctx,
		//trstctl:system-query — auth runs before any tenant is known; the lookup is keyed by the globally-unique, high-entropy token hash and returns the owning tenant. Cross-tenant by design; runs on the pool, not under RLS (AN-1 exemption).
		`SELECT id::text, tenant_id::text, token_hash, subject, scopes, expires_at, created_at,
		        revoked_at, revoked_by, revocation_reason, COALESCE(delegated, false), minted_by
		   FROM api_tokens AS t
		  WHERE t.token_hash = $1 AND t.revoked_at IS NULL
		    AND NOT (COALESCE(t.delegated, false) AND btrim(t.minted_by_ref) = '')
		    AND NOT EXISTS (
		      SELECT 1 FROM api_token_revocation_commands AS c
		       WHERE c.tenant_id = t.tenant_id AND c.token_id = t.id
		    )
		    AND NOT EXISTS (
		      SELECT 1 FROM tenant_member_offboard_commands AS c
		      LEFT JOIN tenant_members AS m ON m.tenant_id = c.tenant_id AND m.subject_ref = c.subject_ref
		       WHERE c.tenant_id = t.tenant_id AND c.subject_ref IN (t.subject_ref, t.minted_by_ref)
		         AND (c.status = 'pending' OR m.status IS DISTINCT FROM 'active')
		    )
		    AND NOT EXISTS (
		      SELECT 1 FROM tenant_members AS m
		       WHERE m.tenant_id = t.tenant_id AND m.subject_ref IN (t.subject_ref, t.minted_by_ref)
		         AND m.status = 'offboarded'
		    )
		    AND NOT EXISTS (
		      SELECT 1 FROM privacy_subject_erasure_preparations AS p
		       WHERE p.tenant_id = t.tenant_id AND p.subject_ref IN (t.subject_ref, t.minted_by_ref)
		    )`, hash).
		Scan(&r.ID, &r.TenantID, &r.TokenHash, &r.Subject, &r.Scopes, &r.ExpiresAt, &r.CreatedAt, &r.RevokedAt, &r.RevokedBy, &r.RevocationReason, &r.Delegated, &r.MintedBy)
	return r, err
}
