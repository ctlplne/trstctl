// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

func TestPostgresBrowserSessionsSurviveReplicaAndProcessReplacement(t *testing.T) {
	st := newServerTestStore(t)
	ctx := context.Background()
	secret := []byte("shared-session-secret-0123456789abcdef")
	tenantID := "11111111-1111-1111-1111-111111111111"

	firstReplica := newBrowserSessionIssuer(secret, time.Hour, st)
	token, err := firstReplica.IssueContext(ctx, "operator@example.test", tenantID, "operator@example.test", []string{"admin"})
	if err != nil {
		t.Fatalf("issue on first replica: %v", err)
	}

	// A separately constructed issuer represents another pod or the replacement
	// process after a rolling restart. It shares only the HMAC secret + PostgreSQL.
	secondReplica := newBrowserSessionIssuer(secret, time.Hour, st)
	session, err := secondReplica.VerifyContext(ctx, token)
	if err != nil {
		t.Fatalf("verify on second replica: %v", err)
	}
	if session.TenantID != tenantID || session.Subject != "operator@example.test" || session.ID == "" {
		t.Fatalf("shared session = %+v", session)
	}

	var sessionHash, subjectHash string
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT session_hash, subject_hash FROM browser_sessions WHERE tenant_id = $1`, tenantID,
	).Scan(&sessionHash, &subjectHash); err != nil {
		t.Fatalf("inspect pseudonymous session row: %v", err)
	}
	if sessionHash != crypto.SHA256Hex([]byte(session.ID)) {
		t.Fatalf("stored session hash = %q, does not bind the raw opaque ID", sessionHash)
	}
	if subjectHash == session.Subject || subjectHash == session.Email {
		t.Fatalf("browser session row retained a raw subject/email: %q", subjectHash)
	}

	if err := firstReplica.RevokeContext(ctx, tenantID, session.ID); err != nil {
		t.Fatalf("revoke on first replica: %v", err)
	}
	if _, err := secondReplica.VerifyContext(ctx, token); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Fatalf("verify revoked session on second replica = %v, want ErrSessionRevoked", err)
	}
}

func TestPostgresBrowserSessionsKeepTenantRowsIsolated(t *testing.T) {
	st := newServerTestStore(t)
	ctx := context.Background()
	secret := []byte("shared-session-secret-0123456789abcdef")
	issuer := newBrowserSessionIssuer(secret, time.Hour, st)
	tenantA := "11111111-1111-1111-1111-111111111111"
	tenantB := "22222222-2222-2222-2222-222222222222"

	tokenA, err := issuer.IssueContext(ctx, "same-subject", tenantA, "", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	tokenB, err := issuer.IssueContext(ctx, "same-subject", tenantB, "", []string{"viewer"})
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.RevokeSubjectContext(ctx, tenantA, "same-subject"); err != nil {
		t.Fatalf("tenant A subject revoke: %v", err)
	}
	if _, err := issuer.VerifyContext(ctx, tokenA); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Fatalf("tenant A session after revoke = %v, want ErrSessionRevoked", err)
	}
	if _, err := issuer.VerifyContext(ctx, tokenB); err != nil {
		t.Fatalf("tenant B session was affected by tenant A revoke: %v", err)
	}
}

func TestPostgresOIDCBackchannelBindsProviderSubjectAndSIDAcrossReplica(t *testing.T) {
	st := newServerTestStore(t)
	ctx := context.Background()
	secret := []byte("shared-oidc-session-secret-0123456789")
	first := newBrowserSessionIssuer(secret, time.Hour, st)
	tenant := "11111111-1111-1111-1111-111111111111"
	now := time.Now().UTC()
	binding := auth.OIDCSessionBinding{Issuer: "https://idp.example.test", ClientID: "trstctl-ui", SID: "idp-session-a", IssuedAt: now.Unix()}
	match, err := first.IssueOIDCContext(ctx, "shared-subject", tenant, "", []string{"viewer"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	binding.SID = "idp-session-b"
	otherSID, err := first.IssueOIDCContext(ctx, "shared-subject", tenant, "", []string{"viewer"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	binding.Issuer = "https://another-idp.example.test"
	otherProvider, err := first.IssueOIDCContext(ctx, "shared-subject", tenant, "", []string{"viewer"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	nonOIDC, err := first.IssueContext(ctx, "shared-subject", tenant, "", []string{"viewer"})
	if err != nil {
		t.Fatal(err)
	}
	// A replacement process receives only the durable store and cookie key.
	second := newBrowserSessionIssuer(secret, time.Hour, st)
	if err := second.RevokeOIDCContext(ctx, tenant, auth.LogoutTokenClaims{
		Issuer: "https://idp.example.test", ClientID: "trstctl-ui", Subject: "shared-subject", SID: "idp-session-a",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := second.VerifyContext(ctx, match); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Fatalf("exact OIDC session after logout = %v", err)
	}
	for name, cookie := range map[string]string{"other IdP sid": otherSID, "other provider": otherProvider, "SAML/LDAP": nonOIDC} {
		if _, err := second.VerifyContext(ctx, cookie); err != nil {
			t.Errorf("%s session was incorrectly revoked: %v", name, err)
		}
	}
}

func TestPostgresLegacyUnboundBrowserSessionFailsClosedAfterBindingMigration(t *testing.T) {
	st := newServerTestStore(t)
	ctx := context.Background()
	tenant := "11111111-1111-1111-1111-111111111111"
	// This row has the exact historical shape: 0195's fields, with 0272's
	// default 'legacy' filling the new binding column during upgrade.
	if _, err := st.SystemPool().Exec(ctx, `INSERT INTO browser_sessions
	    (tenant_id, session_hash, subject_hash, created_at, last_seen_at, expires_at)
	    VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour')`,
		tenant, crypto.SHA256Hex([]byte("historical-cookie")), crypto.SHA256Hex([]byte("historical-subject"))); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetBrowserSession(ctx, tenant, crypto.SHA256Hex([]byte("historical-cookie"))); !store.IsNotFound(err) {
		t.Fatalf("unbound historical browser cookie remained live after migration: %v", err)
	}
}

func TestPostgresOIDCBindingRejectsMissingProviderDigest(t *testing.T) {
	st := newServerTestStore(t)
	now := time.Now().UTC()
	err := st.CreateBrowserSession(context.Background(), store.BrowserSession{
		TenantID:    "11111111-1111-1111-1111-111111111111",
		SessionHash: crypto.SHA256Hex([]byte("oidc-without-provider")),
		SubjectHash: crypto.SHA256Hex([]byte("oidc-subject")),
		ExpiresAt:   now.Add(time.Hour), CreatedAt: now, LastSeenAt: now,
		AuthMethod: "oidc", OIDCIDTokenIat: now.Unix(),
	})
	if err == nil {
		t.Fatal("OIDC browser session without a provider digest was stored")
	}
}
