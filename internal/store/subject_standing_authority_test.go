// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// CR-001: an automatic approval rule applies only while its author may still
// approve access, read from the records the control plane keeps. A subject's
// standing authority is an active member's roles and the scopes of its own
// live API tokens: never a token someone else minted for it, a revoked or
// expired one, or anything of an offboarded subject; and only in its tenant.
func TestSubjectStandingAuthorityReadsOnlyLiveOwnRecordsCR001(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenant, neighbor = "c0010001-0000-4000-8000-000000000001", "c0010002-0000-4000-8000-000000000001"
	seedTenant(t, s, tenant)
	seedTenant(t, s, neighbor)
	now := time.Now().UTC().Truncate(time.Microsecond)
	past := now.Add(-time.Minute)
	token := func(tenantID, subject string, scopes []string, delegated bool, expires *time.Time) string {
		t.Helper()
		id := googleuuid.NewString()
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return s.ApplyAPITokenCreatedTx(ctx, tx, store.APITokenRecord{ID: id, TenantID: tenantID, TokenHash: googleuuid.NewString(),
				Subject: subject, Scopes: scopes, ExpiresAt: expires, CreatedAt: now, Delegated: delegated, EventSequence: 1})
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	member := func(subject string, roles []string, sequence uint64) {
		t.Helper()
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplyTenantMemberUpsertedTx(ctx, tx, store.TenantMember{TenantID: tenant, Subject: subject, DisplayName: subject,
				Roles: roles, Source: "manual", Status: "active", CreatedAt: now, UpdatedAt: now, EventSequence: sequence})
		}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(tenantID, subject string) store.SubjectStandingAuthority {
		t.Helper()
		held, err := s.GetSubjectStandingAuthority(ctx, tenantID, subject, now)
		if err != nil {
			t.Fatal(err)
		}
		return held
	}

	// A subject's own live tokens give their scopes; a delegated, expired or
	// revoked token gives nothing, and neither does another tenant's.
	const approver = "approver@example.test"
	token(tenant, approver, []string{"access:read", "access:approve"}, false, nil)
	token(tenant, approver, []string{"secrets:read"}, true, nil)
	token(tenant, approver, []string{"keys:read"}, false, &past)
	revoked := token(tenant, approver, []string{"certs:issue"}, false, nil)
	if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		return s.ApplyAPITokenRevokedTx(ctx, tx, tenant, revoked, "admin", "rotated", now)
	}); err != nil {
		t.Fatal(err)
	}
	token(neighbor, approver, []string{"audit:read"}, false, nil)
	if got := read(tenant, approver); !slices.Equal(got.TokenScopes, []string{"access:approve", "access:read"}) || len(got.MemberRoles) != 0 {
		t.Fatalf("approver's standing authority = %+v, want only its own live token's scopes", got)
	}

	// An active member's roles, as its record names them now.
	member(approver, []string{"operator"}, 1)
	if got := read(tenant, approver); !slices.Equal(got.MemberRoles, []string{"operator"}) {
		t.Fatalf("member roles = %+v", got.MemberRoles)
	}
	member(approver, []string{"viewer"}, 2)
	if got := read(tenant, approver); !slices.Equal(got.MemberRoles, []string{"viewer"}) {
		t.Fatalf("lowered member roles = %+v", got.MemberRoles)
	}

	// An offboarded subject holds nothing, its member roles nor its tokens.
	if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		return s.ApplyTenantMemberOffboardedTx(ctx, tx, store.TenantMember{TenantID: tenant, Subject: approver, UpdatedAt: now,
			OffboardedBy: "admin", OffboardReason: "left", EventSequence: 3})
	}); err != nil {
		t.Fatal(err)
	}
	if got := read(tenant, approver); len(got.MemberRoles) != 0 || len(got.TokenScopes) != 0 {
		t.Fatalf("offboarded subject's standing authority = %+v, want none", got)
	}

	// A subject the tenant never heard of holds nothing.
	if got := read(tenant, "stranger@example.test"); len(got.MemberRoles) != 0 || len(got.TokenScopes) != 0 {
		t.Fatalf("unknown subject's standing authority = %+v", got)
	}
}
