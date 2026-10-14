// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/tenancy"
)

// oidcAuthPartition is an internal, non-customer RLS partition. A logout_token
// cannot name a trstctl tenant, so its indexed locator and durable JTI receipt
// live here while each browser session remains in its real tenant partition.
const oidcAuthPartition = "00000000-0000-0000-0000-000000000002"

var (
	ErrOIDCLoginLoggedOut      = errors.New("store: OIDC login was cut off by IdP logout")
	ErrOIDCLogoutJTIConflict   = errors.New("store: OIDC logout JTI belongs to a different assertion")
	ErrOIDCAuthPartitionTenant = errors.New("store: reserved OIDC auth partition cannot be a browser tenant")
)

// OIDCBackchannelLogout contains only digests of the verified assertion and
// its bound identities. The raw signed JWT and subject never reach PostgreSQL.
type OIDCBackchannelLogout struct {
	ProviderHash      string
	GlobalSubjectHash string
	SIDHash           string
	JTIHash           string
	AssertionHash     string
	IssuedAt          int64
	ExpiresAt         int64
	CompletedAt       time.Time
}

func setOIDCAuthScopeTx(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SET LOCAL search_path TO public"); err != nil {
		return fmt.Errorf("store: route OIDC auth partition: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('trstctl.tenant_id', $1, true)", oidcAuthPartition); err != nil {
		return fmt.Errorf("store: scope OIDC auth partition: %w", err)
	}
	return nil
}

func setOIDCCustomerScopeTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	schema, err := tenancy.PostgresSchema(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("store: resolve OIDC browser tenant route: %w", err)
	}
	if schema == "" {
		if _, err := tx.Exec(ctx, "SET LOCAL search_path TO public"); err != nil {
			return fmt.Errorf("store: route pooled OIDC browser tenant: %w", err)
		}
	} else if _, err := tx.Exec(ctx, "SET LOCAL search_path TO "+pgx.Identifier{schema}.Sanitize()+", public"); err != nil {
		return fmt.Errorf("store: route siloed OIDC browser tenant: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('trstctl.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("store: scope OIDC browser tenant: %w", err)
	}
	return nil
}

// Login and logout take the same sorted provider/subject/sid locks before
// reading a cutoff or writing a session. If login commits first, logout finds
// its locator; if logout commits first, login observes the durable cutoff.
func lockOIDCIdentityTx(ctx context.Context, tx pgx.Tx, providerHash, globalSubjectHash, sidHash string) error {
	identities := make([]string, 0, 2)
	if globalSubjectHash != "" {
		identities = append(identities, "subject:"+globalSubjectHash)
	}
	if sidHash != "" {
		identities = append(identities, "sid:"+sidHash)
	}
	if providerHash == "" || len(identities) == 0 {
		return errors.New("store: OIDC provider and subject or sid are required")
	}
	sort.Strings(identities)
	for _, identity := range identities {
		if err := lockUpsertArbiterTx(ctx, tx, "oidc_logout_identity", providerHash, identity); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) prepareOIDCBrowserCreateTx(ctx context.Context, tx pgx.Tx, session BrowserSession) error {
	if session.OIDCProviderHash == "" || session.OIDCGlobalSubjectHash == "" || session.OIDCIDTokenIat <= 0 {
		return errors.New("store: OIDC browser binding is incomplete")
	}
	if err := lockOIDCIdentityTx(ctx, tx, session.OIDCProviderHash, session.OIDCGlobalSubjectHash, session.OIDCSIDHash); err != nil {
		return err
	}
	if err := setOIDCAuthScopeTx(ctx, tx); err != nil {
		return err
	}
	var cutOff bool
	if err := tx.QueryRow(ctx, `SELECT
	    EXISTS (SELECT 1 FROM oidc_logout_receipts
	             WHERE tenant_id = $1 AND provider_hash = $2
	               AND sid_hash = NULLIF($3, '')
	               AND (global_subject_hash IS NULL OR global_subject_hash = $4))
	 OR EXISTS (SELECT 1 FROM oidc_logout_receipts
	             WHERE tenant_id = $1 AND provider_hash = $2
	               AND sid_hash IS NULL AND global_subject_hash = $4
	               AND logout_iat >= $5)`, oidcAuthPartition,
		session.OIDCProviderHash, session.OIDCSIDHash, session.OIDCGlobalSubjectHash,
		session.OIDCIDTokenIat).Scan(&cutOff); err != nil {
		return fmt.Errorf("store: inspect OIDC logout cutoff: %w", err)
	}
	if cutOff {
		return ErrOIDCLoginLoggedOut
	}
	return setOIDCCustomerScopeTx(ctx, tx, session.TenantID)
}

func insertOIDCBrowserLocatorTx(ctx context.Context, tx pgx.Tx, session BrowserSession) error {
	if err := setOIDCAuthScopeTx(ctx, tx); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO oidc_session_locators
	    (tenant_id, browser_tenant_id, session_hash, provider_hash,
	     global_subject_hash, browser_subject_hash, sid_hash, id_token_iat, expires_at)
	    VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, $9)`,
		oidcAuthPartition, session.TenantID, session.SessionHash,
		session.OIDCProviderHash, session.OIDCGlobalSubjectHash, session.SubjectHash,
		session.OIDCSIDHash, session.OIDCIDTokenIat, session.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: insert OIDC browser locator: %w", err)
	}
	return nil
}

type oidcLocatedSession struct {
	tenantID    string
	sessionHash string
	subjectHash string
	issuedAt    int64
}

// ApplyOIDCBackchannelLogout atomically revokes every indexed matching browser
// session and records the exact signed assertion. A failure rolls back both;
// an exact lost-response retry returns the committed result, whereas a changed
// assertion reusing the JTI is refused.
func (s *Store) ApplyOIDCBackchannelLogout(ctx context.Context, logout OIDCBackchannelLogout) error {
	if logout.ProviderHash == "" || logout.JTIHash == "" || logout.AssertionHash == "" ||
		(logout.GlobalSubjectHash == "" && logout.SIDHash == "") ||
		logout.IssuedAt <= 0 || logout.ExpiresAt <= logout.IssuedAt {
		return errors.New("store: OIDC logout binding is incomplete")
	}
	return s.WithTenant(ctx, oidcAuthPartition, func(tx pgx.Tx) error {
		if err := setOIDCAuthScopeTx(ctx, tx); err != nil {
			return err
		}
		if err := lockOIDCIdentityTx(ctx, tx, logout.ProviderHash, logout.GlobalSubjectHash, logout.SIDHash); err != nil {
			return err
		}
		if err := lockUpsertArbiterTx(ctx, tx, "oidc_logout_receipts", logout.ProviderHash, logout.JTIHash); err != nil {
			return err
		}
		var priorAssertion string
		err := tx.QueryRow(ctx, `SELECT assertion_hash FROM oidc_logout_receipts
		    WHERE tenant_id = $1 AND provider_hash = $2 AND jti_hash = $3`,
			oidcAuthPartition, logout.ProviderHash, logout.JTIHash).Scan(&priorAssertion)
		if err == nil {
			if priorAssertion == logout.AssertionHash {
				return nil
			}
			return ErrOIDCLogoutJTIConflict
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("store: inspect OIDC logout receipt: %w", err)
		}
		located, err := locateOIDCSessionsTx(ctx, tx, logout)
		if err != nil {
			return err
		}
		var revoked int
		for _, rec := range located {
			if err := setOIDCCustomerScopeTx(ctx, tx, rec.tenantID); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `UPDATE browser_sessions
			    SET revoked_at = COALESCE(revoked_at, $7)
			  WHERE tenant_id = $1 AND session_hash = $2 AND auth_method = 'oidc'
			    AND oidc_provider_hash = $3 AND subject_hash = $4
			    AND ($5 = '' OR oidc_sid_hash = $5)
			    AND ($6 OR oidc_id_token_iat <= $8)
			    AND revoked_at IS NULL`, rec.tenantID, rec.sessionHash,
				logout.ProviderHash, rec.subjectHash, logout.SIDHash,
				logout.SIDHash != "", logout.CompletedAt, logout.IssuedAt)
			if err != nil {
				return fmt.Errorf("store: revoke located OIDC browser session: %w", err)
			}
			revoked += int(tag.RowsAffected())
		}
		if err := setOIDCAuthScopeTx(ctx, tx); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO oidc_logout_receipts
		    (tenant_id, provider_hash, jti_hash, assertion_hash,
		     global_subject_hash, sid_hash, logout_iat, token_exp,
		     completed_at, revoked_sessions)
		    VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8, $9, $10)`,
			oidcAuthPartition, logout.ProviderHash, logout.JTIHash, logout.AssertionHash,
			logout.GlobalSubjectHash, logout.SIDHash, logout.IssuedAt,
			logout.ExpiresAt, logout.CompletedAt, revoked)
		if err != nil {
			return fmt.Errorf("store: record OIDC logout receipt: %w", err)
		}
		return nil
	})
}

func locateOIDCSessionsTx(ctx context.Context, tx pgx.Tx, logout OIDCBackchannelLogout) ([]oidcLocatedSession, error) {
	query := `SELECT browser_tenant_id::text, session_hash, browser_subject_hash, id_token_iat
	    FROM oidc_session_locators
	    WHERE tenant_id = $1 AND provider_hash = $2`
	args := []any{oidcAuthPartition, logout.ProviderHash}
	if logout.SIDHash != "" {
		args = append(args, logout.SIDHash)
		query += fmt.Sprintf(" AND sid_hash = $%d", len(args))
	}
	if logout.GlobalSubjectHash != "" {
		args = append(args, logout.GlobalSubjectHash)
		query += fmt.Sprintf(" AND global_subject_hash = $%d", len(args))
	}
	if logout.SIDHash == "" {
		args = append(args, logout.IssuedAt)
		query += fmt.Sprintf(" AND id_token_iat <= $%d", len(args))
	}
	args = append(args, logout.CompletedAt)
	query += fmt.Sprintf(" AND expires_at > $%d ORDER BY browser_tenant_id, session_hash", len(args))
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: locate OIDC browser sessions: %w", err)
	}
	defer rows.Close()
	var located []oidcLocatedSession
	for rows.Next() {
		var rec oidcLocatedSession
		if err := rows.Scan(&rec.tenantID, &rec.sessionHash, &rec.subjectHash, &rec.issuedAt); err != nil {
			return nil, err
		}
		located = append(located, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate OIDC browser locators: %w", err)
	}
	return located, nil
}
