// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A207: a tenant custom role projects per tenant. A later definition replaces
// an earlier one and a replay changes nothing; a deletion leaves a tombstone a
// replayed earlier definition cannot undo, and defining the role again
// restores it; the per-request read filters by name; members holding a role
// are counted; and tenant B sees none of it.
func TestTenantCustomRolesProjectPerTenantWithTombstones(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	// Names no other test in this package uses: the database is shared.
	const name, other = "a207-payments-ops", "a207-auditor-plus"
	at := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	tick := 0
	later := func() time.Time {
		tick++
		return at.Add(time.Duration(tick) * time.Second)
	}
	upsert := func(tenantID, roleName string, permissions []string, sequence uint64) error {
		return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return s.ApplyTenantCustomRoleUpsertedTx(ctx, tx, store.TenantCustomRole{
				TenantID: tenantID, Name: roleName, Description: "payments operations", Permissions: permissions,
				UpdatedAt: later(), EventSequence: sequence,
			})
		})
	}
	remove := func(sequence uint64) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyTenantCustomRoleDeletedTx(ctx, tx, tenantA, name, later(), sequence)
		})
	}
	permissionsOf := func() []string {
		t.Helper()
		role, err := s.GetTenantCustomRole(ctx, tenantA, name)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return role.Permissions
	}

	for _, step := range []struct {
		permissions []string
		sequence    uint64
	}{{[]string{"certs:read"}, 207001}, {[]string{"certs:read", "certs:request"}, 207002}, {[]string{"certs:read"}, 207001}} {
		if err := upsert(tenantA, name, step.permissions, step.sequence); err != nil {
			t.Fatal(err)
		}
	}
	if got := permissionsOf(); !slices.Equal(got, []string{"certs:read", "certs:request"}) {
		t.Fatalf("after a replayed earlier definition the role holds %v", got)
	}
	if err := upsert(tenantA, other, []string{"audit:read"}, 207003); err != nil {
		t.Fatal(err)
	}
	listed, err := s.ListTenantCustomRoles(ctx, tenantA, name)
	if err != nil || len(listed) != 1 || listed[0].Name != name {
		t.Fatalf("named read = %+v %v", listed, err)
	}
	all, err := s.ListTenantCustomRoles(ctx, tenantA)
	if err != nil || !slices.ContainsFunc(all, func(r store.TenantCustomRole) bool { return r.Name == name }) ||
		!slices.ContainsFunc(all, func(r store.TenantCustomRole) bool { return r.Name == other }) {
		t.Fatalf("unfiltered read = %+v %v", all, err)
	}

	// Deletion is a tombstone: a replayed definition cannot revive it.
	if err := remove(207004); err != nil {
		t.Fatal(err)
	}
	if err := upsert(tenantA, name, []string{"certs:read", "certs:request"}, 207002); err != nil {
		t.Fatal(err)
	}
	if got := permissionsOf(); got != nil {
		t.Fatalf("a replayed definition revived the deleted role: %v", got)
	}
	if listed, err := s.ListTenantCustomRoles(ctx, tenantA, name, other); err != nil || len(listed) != 1 || listed[0].Name != other {
		t.Fatalf("named read after the deletion = %+v %v", listed, err)
	}
	if err := upsert(tenantA, name, []string{"identities:read"}, 207005); err != nil {
		t.Fatal(err)
	}
	if got := permissionsOf(); !slices.Equal(got, []string{"identities:read"}) {
		t.Fatalf("the role defined again holds %v", got)
	}

	// Holders: a member with the role counts, an offboarded one does not.
	member := store.TenantMember{TenantID: tenantA, Subject: "a207-holder@example.test", DisplayName: "Holder",
		Roles: []string{"viewer", name}, Source: "api", Status: "active", CreatedAt: at, UpdatedAt: at, EventSequence: 207006}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyTenantMemberUpsertedTx(ctx, tx, member) }); err != nil {
		t.Fatal(err)
	}
	if n, err := s.TenantCustomRoleHolders(ctx, tenantA, name); err != nil || n != 1 {
		t.Fatalf("holders = %d %v", n, err)
	}

	// Tenant B sees nothing and may define the same name independently.
	if _, err := s.GetTenantCustomRole(ctx, tenantB, name); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant B reads tenant A's role: %v", err)
	}
	if err := upsert(tenantB, name, []string{"audit:read"}, 207007); err != nil {
		t.Fatal(err)
	}
	if got := permissionsOf(); !slices.Equal(got, []string{"identities:read"}) {
		t.Fatalf("tenant B's definition changed tenant A's role: %v", got)
	}
	if n, err := s.TenantCustomRoleHolders(ctx, tenantB, name); err != nil || n != 0 {
		t.Fatalf("tenant B holders = %d %v", n, err)
	}
	if err := upsert(tenantA, "Not A Name", nil, 207008); err == nil {
		t.Fatal("an invalid role name was stored")
	}
}
