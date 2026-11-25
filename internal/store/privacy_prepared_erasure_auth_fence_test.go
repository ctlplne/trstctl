// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

// A prepared erasure must deny authentication on every replica before the
// final privacy.subject.erased event projects. This test prepares the erasure
// without completing it, then checks four authority readers on two stores
// sharing only PostgreSQL.
func TestCR406PreparedPrivacyErasureDeniesAuthenticationOnEveryReplica(t *testing.T) {
	ctx := context.Background()
	st := newOperationApprovalStore(t)
	const subject = "vh48-prepared-erasure-subject@example.test"
	now := time.Now().UTC().Truncate(time.Microsecond)
	subjectRef := privacy.SubjectRef(tenantA, subject)

	// An active tenant member with an API token and a live browser session.
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyTenantMemberUpsertedTx(ctx, tx, store.TenantMember{
			TenantID: tenantA, Subject: subject, DisplayName: "VH48 subject",
			Roles: []string{"operator"}, Source: "manual", Status: "active",
			CreatedAt: now, UpdatedAt: now, EventSequence: 1,
		})
	}); err != nil {
		t.Fatalf("seed active member: %v", err)
	}
	tokenHash := privacy.SubjectRef(tenantA, "cr406-test-token")
	if _, err := st.CreateAPIToken(ctx, store.APITokenRecord{
		TenantID: tenantA, TokenHash: tokenHash, Subject: subject, Scopes: []string{"access:read"},
	}); err != nil {
		t.Fatalf("create api token: %v", err)
	}
	newSession := func(label string) store.BrowserSession {
		return store.BrowserSession{
			TenantID: tenantA, SessionHash: privacy.SubjectRef(tenantA, "vh48-session-"+label),
			SubjectHash: subjectRef, ExpiresAt: now.Add(time.Hour), CreatedAt: now, LastSeenAt: now,
			AuthMethod: "other",
		}
	}
	existing := newSession("existing")
	if err := st.CreateBrowserSession(ctx, existing); err != nil {
		t.Fatalf("create browser session: %v", err)
	}

	// readers returns the readers that still admit the subject on one replica.
	readers := func(replica string, s *store.Store, signInLabel string) []string {
		t.Helper()
		var admit []string
		if _, err := s.LookupAPITokenByHash(ctx, tokenHash); err == nil {
			admit = append(admit, "api-token-lookup")
		} else if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("%s: API-token lookup failed instead of refusing: %v", replica, err)
		}
		if err := s.CreateBrowserSession(ctx, newSession(signInLabel)); err == nil {
			admit = append(admit, "browser-session-check")
		} else if !errors.Is(err, store.ErrTenantMemberOffboarded) {
			t.Fatalf("%s: browser-session creation failed instead of refusing: %v", replica, err)
		}
		if _, err := s.GetBrowserSession(ctx, tenantA, existing.SessionHash); err != nil {
			t.Fatalf("%s: existing cookie session lookup: %v", replica, err)
		}
		denied, err := s.MemberOffboardStatus(ctx, tenantA, subject)
		if err != nil {
			t.Fatalf("%s: member-status check failed: %v", replica, err)
		}
		if !denied {
			admit = append(admit, "member-status-check")
		}
		if held, err := s.GetSubjectStandingAuthority(ctx, tenantA, subject, now); err == nil &&
			(len(held.MemberRoles) != 0 || len(held.TokenScopes) != 0) {
			admit = append(admit, "standing-authority")
		} else if err != nil {
			t.Fatalf("%s: standing authority lookup: %v", replica, err)
		}
		return admit
	}
	if before := readers("replica-1 before preparation", st, "before"); len(before) != 4 {
		t.Fatalf("fixture: all four readers must admit the active member before preparation, admitted %v", before)
	}

	candidate := store.PrivacySubjectErasurePreparation{
		PrivacySubjectErasure: store.PrivacySubjectErasure{
			TenantID: tenantA, SubjectRef: subjectRef,
			RequestedByRef: privacy.SubjectRef(tenantA, "privacy-admin"),
			Reason:         "verified erasure", ErasedAt: now,
		},
		OperationID:        "sha256:" + strings.Repeat("4", 64),
		RequestBinding:     strings.Repeat("5", 64),
		EventID:            "sha256:" + strings.Repeat("6", 64),
		RewriteOperationID: "vh48-prepared-erasure-rewrite",
		TargetGeneration:   "vh48-prepared-erasure-generation",
		EventActor:         &events.Actor{Subject: privacy.Placeholder(privacy.SubjectRef(tenantA, "privacy-admin"))},
	}
	if _, err := st.PreparePrivacySubjectErasure(ctx, tenantA, subject, candidate); err != nil {
		t.Fatalf("prepare privacy subject erasure: %v", err)
	}
	// Preconditions of the window: the durable preparation row exists and the
	// completion has not projected (the member read model is still active).
	if _, err := st.GetPrivacySubjectErasurePreparation(ctx, tenantA, candidate.OperationID); err != nil {
		t.Fatalf("preparation row missing: %v", err)
	}
	if m, err := st.GetTenantMember(ctx, tenantA, subject); err != nil || m.Status != "active" {
		t.Fatalf("privacy.subject.erased must not have projected: member=%+v err=%v", m, err)
	}

	// Replica 1: the store that prepared the erasure.
	if admit := readers("replica-1 after preparation", st, "replica-1"); len(admit) != 0 {
		t.Errorf("replica-1: prepared privacy erasure still authenticates through %v", admit)
	}
	// Replica 2: a separate store instance (own pool, no shared in-process
	// state) on the same database, as a second control-plane replica would be.
	second, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("open second replica store: %v", err)
	}
	defer second.Close()
	if admit := readers("replica-2 after preparation", second, "replica-2"); len(admit) != 0 {
		t.Errorf("replica-2: prepared privacy erasure still authenticates through %v", admit)
	}
}
