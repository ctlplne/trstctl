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

func TestPostgresOIDCBackchannelClaimTenantReceiptAndLateLoginAcrossReplica(t *testing.T) {
	st := newServerTestStore(t)
	ctx := context.Background()
	secret := []byte("shared-oidc-logout-secret-0123456789")
	first := newBrowserSessionIssuer(secret, time.Hour, st)
	second := newBrowserSessionIssuer(secret, time.Hour, st)
	tenantA := "11111111-1111-1111-1111-111111111111"
	tenantB := "22222222-2222-2222-2222-222222222222"
	now := time.Now().UTC()
	binding := auth.OIDCSessionBinding{Issuer: "https://idp.example.test", ClientID: "trstctl-ui", IssuedAt: now.Unix()}
	var matching []string
	for _, tenantID := range []string{tenantA, tenantB} {
		cookie, err := first.IssueOIDCContext(ctx, "claim-user", tenantID, "", []string{"viewer"}, binding)
		if err != nil {
			t.Fatal(err)
		}
		matching = append(matching, cookie)
	}
	unrelated, err := first.IssueOIDCContext(ctx, "other-user", tenantA, "", []string{"viewer"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	nonOIDC, err := first.IssueContext(ctx, "claim-user", tenantA, "", []string{"viewer"})
	if err != nil {
		t.Fatal(err)
	}
	claims := auth.LogoutTokenClaims{
		Issuer: binding.Issuer, ClientID: binding.ClientID, Subject: "claim-user",
		JTI: "claim-tenant-jti-1", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	}
	assertionHash := crypto.SHA256Hex([]byte("exact-signed-logout-assertion"))
	if err := second.LogoutOIDCContext(ctx, claims, assertionHash); err != nil {
		t.Fatalf("logout from replacement replica: %v", err)
	}
	for _, cookie := range matching {
		if _, err := first.VerifyContext(ctx, cookie); !errors.Is(err, auth.ErrSessionRevoked) {
			t.Fatalf("claim-derived tenant cookie remained authorized: %v", err)
		}
	}
	for name, cookie := range map[string]string{"unrelated OIDC subject": unrelated, "same-subject non-OIDC": nonOIDC} {
		if _, err := first.VerifyContext(ctx, cookie); err != nil {
			t.Fatalf("%s was revoked by the assertion: %v", name, err)
		}
	}
	third := newBrowserSessionIssuer(secret, time.Hour, st)
	if err := third.LogoutOIDCContext(ctx, claims, assertionHash); err != nil {
		t.Fatalf("exact committed assertion was not retryable after process replacement: %v", err)
	}
	if err := third.LogoutOIDCContext(ctx, claims, crypto.SHA256Hex([]byte("different-signed-assertion"))); !errors.Is(err, auth.ErrLogoutTokenReplay) {
		t.Fatalf("changed assertion reused a committed JTI: %v", err)
	}
	if _, err := third.IssueOIDCContext(ctx, "claim-user", tenantB, "", []string{"viewer"}, binding); !errors.Is(err, auth.ErrOIDCSessionLoggedOut) {
		t.Fatalf("late callback with pre-logout ID token escaped cutoff: %v", err)
	}
	binding.IssuedAt = now.Unix() + 1
	if _, err := third.IssueOIDCContext(ctx, "claim-user", tenantB, "", []string{"viewer"}, binding); err != nil {
		t.Fatalf("fresh post-logout IdP session was refused: %v", err)
	}
}

func TestPostgresOIDCBackchannelSIDAndSubjectIntersection(t *testing.T) {
	st := newServerTestStore(t)
	ctx := context.Background()
	issuer := newBrowserSessionIssuer([]byte("oidc-sid-intersection-secret-012345"), time.Hour, st)
	now := time.Now().UTC()
	tenantA := "11111111-1111-1111-1111-111111111111"
	tenantB := "22222222-2222-2222-2222-222222222222"
	binding := auth.OIDCSessionBinding{Issuer: "https://idp.example.test", ClientID: "trstctl-ui", SID: "same-sid", IssuedAt: now.Unix()}
	match, err := issuer.IssueOIDCContext(ctx, "subject-a", tenantA, "", []string{"viewer"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	otherSubject, err := issuer.IssueOIDCContext(ctx, "subject-b", tenantB, "", []string{"viewer"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	binding.SID = "other-sid"
	otherSID, err := issuer.IssueOIDCContext(ctx, "subject-a", tenantA, "", []string{"viewer"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	base := auth.LogoutTokenClaims{Issuer: binding.Issuer, ClientID: binding.ClientID,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	intersection := base
	intersection.Subject, intersection.SID, intersection.JTI = "subject-a", "same-sid", "intersection-jti"
	if err := issuer.LogoutOIDCContext(ctx, intersection, crypto.SHA256Hex([]byte("intersection-assertion"))); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.VerifyContext(ctx, match); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Fatalf("matching subject+sid remained live: %v", err)
	}
	for name, cookie := range map[string]string{"other subject": otherSubject, "other sid": otherSID} {
		if _, err := issuer.VerifyContext(ctx, cookie); err != nil {
			t.Fatalf("%s revoked by intersection: %v", name, err)
		}
	}
	sidOnly := base
	sidOnly.SID, sidOnly.JTI = "same-sid", "sid-only-jti"
	if err := issuer.LogoutOIDCContext(ctx, sidOnly, crypto.SHA256Hex([]byte("sid-only-assertion"))); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.VerifyContext(ctx, otherSubject); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Fatalf("sid-only logout missed a second tenant's cookie: %v", err)
	}
	if _, err := issuer.VerifyContext(ctx, otherSID); err != nil {
		t.Fatalf("sid-only logout revoked another IdP session: %v", err)
	}
	if _, err := issuer.IssueOIDCContext(ctx, "subject-b", tenantB, "", []string{"viewer"},
		auth.OIDCSessionBinding{Issuer: binding.Issuer, ClientID: binding.ClientID, SID: "same-sid", IssuedAt: now.Unix() + 1}); !errors.Is(err, auth.ErrOIDCSessionLoggedOut) {
		t.Fatalf("late login reused signed-out sid: %v", err)
	}
}

func TestPostgresOIDCLocatorRemovedWithSubjectAuthority(t *testing.T) {
	st := newServerTestStore(t)
	ctx := context.Background()
	tenantID := "11111111-1111-1111-1111-111111111111"
	issuer := newBrowserSessionIssuer([]byte("oidc-subject-revoke-secret-0123456"), time.Hour, st)
	now := time.Now().UTC()
	cookie, err := issuer.IssueOIDCContext(ctx, "erased-operator", tenantID, "", []string{"viewer"},
		auth.OIDCSessionBinding{Issuer: "https://idp.example.test", ClientID: "trstctl-ui", IssuedAt: now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	const authPartition = "00000000-0000-0000-0000-000000000002"
	count := func() int {
		t.Helper()
		var n int
		if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM oidc_session_locators
		    WHERE tenant_id = $1 AND browser_tenant_id = $2`, authPartition, tenantID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := count(); got != 1 {
		t.Fatalf("precondition: OIDC locator rows = %d, want 1", got)
	}
	if err := st.RevokeBrowserSessionsBySubject(ctx, tenantID,
		browserSessionSubjectHash(tenantID, "erased-operator"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.VerifyContext(ctx, cookie); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Fatalf("subject authority removal left cookie usable: %v", err)
	}
	if got := count(); got != 0 {
		t.Fatalf("subject authority removal left %d global locators", got)
	}
}

func TestPostgresOIDCAuthPartitionCannotBeCustomerTenant(t *testing.T) {
	st := newServerTestStore(t)
	const reserved = "00000000-0000-0000-0000-000000000002"
	if err := st.UpsertTenant(context.Background(), store.Tenant{TenantID: reserved, Name: "forbidden"}); err == nil {
		t.Fatal("internal OIDC authority partition accepted a customer registration")
	}
	issuer := newBrowserSessionIssuer([]byte("oidc-reserved-tenant-secret-0123456"), time.Hour, st)
	if _, err := issuer.IssueOIDCContext(context.Background(), "subject", reserved, "", []string{"viewer"},
		auth.OIDCSessionBinding{Issuer: "https://idp.example.test", ClientID: "trstctl-ui", IssuedAt: time.Now().Unix()}); err == nil {
		t.Fatal("internal OIDC authority partition accepted a browser cookie")
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

func TestPostgresPreLocatorOIDCCookieFailsClosedAfterUpgrade(t *testing.T) {
	st := newServerTestStore(t)
	ctx := context.Background()
	tenant := "11111111-1111-1111-1111-111111111111"
	sessionHash := crypto.SHA256Hex([]byte("pre-locator-oidc-cookie"))
	if _, err := st.SystemPool().Exec(ctx, `INSERT INTO browser_sessions
	    (tenant_id, session_hash, subject_hash, created_at, last_seen_at, expires_at,
	     auth_method, oidc_provider_hash, oidc_id_token_iat)
	    VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour',
	      'oidc', $4, extract(epoch from now())::bigint)`,
		tenant, sessionHash, crypto.SHA256Hex([]byte("pre-locator-subject")),
		crypto.SHA256Hex([]byte("pre-locator-provider"))); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetBrowserSession(ctx, tenant, sessionHash); !store.IsNotFound(err) {
		t.Fatalf("unlocatable pre-upgrade OIDC cookie remained usable: %v", err)
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
