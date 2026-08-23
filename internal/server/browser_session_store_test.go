// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto"
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
