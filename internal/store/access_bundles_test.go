// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A251: the access bundle projections. A deleted bundle stays deleted
// whatever arrives after; an older revision never replaces a newer one; a
// permission two grants give survives the removal of one; a user grant gives
// nothing once its member is offboarded; a run holds only what its grants still
// give; and every applied event leaves exactly one activity row, keyed by its
// event ID.
func TestAccessBundleProjectionsA251(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenant = "a2510000-0000-4000-8000-000000000001"
	seedTenant(t, s, tenant)
	now := time.Now().UTC().Truncate(time.Microsecond)
	seq := uint64(100)
	apply := func(fn func(tx pgx.Tx, eventID string, sequence uint64) error) string {
		t.Helper()
		seq++
		id := googleuuid.NewString()
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error { return fn(tx, id, seq) }); err != nil {
			t.Fatal(err)
		}
		return id
	}
	save := func(b store.AccessBundle) string {
		return apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
			return s.ApplyAccessBundleSavedTx(ctx, tx, tenant, b, eventID, sequence)
		})
	}
	bundleA := store.AccessBundle{ID: googleuuid.NewString(), Name: "deploy-full", Permissions: []string{"certs:read", "owners:read"},
		Audiences: []string{"ci"}, MaxRunTTLSeconds: 900, Revision: 1, CreatedBy: "admin", CreatedAt: now}
	bundleB := store.AccessBundle{ID: googleuuid.NewString(), Name: "deploy-owners", Permissions: []string{"owners:read"},
		Audiences: []string{}, MaxRunTTLSeconds: 900, Revision: 1, CreatedBy: "admin", CreatedAt: now}
	save(bundleA)
	save(bundleB)

	// Revision 3 then a late revision 2: revision 3 stays.
	r3 := bundleA
	r3.Revision, r3.Permissions = 3, []string{"certs:read", "identities:read", "owners:read"}
	save(r3)
	r2 := bundleA
	r2.Revision, r2.Permissions = 2, []string{"certs:read"}
	save(r2)
	if got, err := s.GetAccessBundle(ctx, tenant, bundleA.ID); err != nil || got.Revision != 3 || len(got.Permissions) != 3 {
		t.Fatalf("after a late revision 2: %+v %v", got, err)
	}

	grant := func(bundleID, principalType, principal string, expires *time.Time) string {
		g := store.AccessBundleGrant{ID: googleuuid.NewString(), BundleID: bundleID, PrincipalType: principalType, Principal: principal,
			ExpiresAt: expires, GrantedBy: "admin", GrantedAt: now}
		apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
			return s.ApplyAccessBundleGrantedTx(ctx, tx, tenant, g, eventID, sequence)
		})
		return g.ID
	}
	gA := grant(bundleA.ID, "machine", "ci:deploy", nil)
	gB := grant(bundleB.ID, "machine", "ci:deploy", nil)
	expired := now.Add(-time.Minute)
	grant(bundleA.ID, "machine", "ci:stale", &expired)

	held, err := s.EffectiveAuthority(ctx, tenant, "ci:deploy", now)
	if err != nil || len(held["owners:read"]) != 2 || len(held["certs:read"]) != 1 || len(held["identities:read"]) != 1 {
		t.Fatalf("authority with two grants = %+v %v", held, err)
	}
	if held, err := s.EffectiveAuthority(ctx, tenant, "ci:stale", now); err != nil || len(held) != 0 {
		t.Fatalf("an expired grant gives %+v %v", held, err)
	}

	runID := googleuuid.NewString()
	apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
		return s.ApplyAccessBundleRunIssuedTx(ctx, tx, tenant, store.AccessBundleRun{ID: runID, Principal: "ci:deploy",
			BundleIDs: []string{bundleA.ID, bundleB.ID}, GrantIDs: []string{gA, gB}, Permissions: []string{"certs:read", "owners:read"},
			Label: "deploy #7", ExpiresAt: now.Add(10 * time.Minute), IssuedBy: "ci:deploy", IssuedAt: now}, eventID, sequence)
	})
	if _, allowed, err := s.RunAuthority(ctx, tenant, runID, now); err != nil || !slices.Equal(allowed, []string{"certs:read", "owners:read"}) {
		t.Fatalf("run authority = %v %v", allowed, err)
	}

	ungrant := func(id string) {
		apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
			return s.ApplyAccessBundleUngrantedTx(ctx, tx, tenant, id, "admin", "rotated", now, eventID, sequence)
		})
	}
	ungrant(gA)
	held, err = s.EffectiveAuthority(ctx, tenant, "ci:deploy", now)
	if err != nil || len(held) != 1 || len(held["owners:read"]) != 1 || held["owners:read"][0].BundleName != "deploy-owners" {
		t.Fatalf("authority after removing one grant = %+v %v", held, err)
	}
	if _, allowed, err := s.RunAuthority(ctx, tenant, runID, now); err != nil || !slices.Equal(allowed, []string{"owners:read"}) {
		t.Fatalf("run authority after removing one grant = %v %v", allowed, err)
	}
	if _, allowed, err := s.RunAuthority(ctx, tenant, runID, now.Add(11*time.Minute)); err != nil || allowed != nil {
		t.Fatalf("an expired run holds %v %v", allowed, err)
	}

	// Delete B: a late save of a newer revision cannot bring it back.
	apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
		return s.ApplyAccessBundleDeletedTx(ctx, tx, tenant, bundleB.ID, "admin", now, eventID, sequence)
	})
	late := bundleB
	late.Revision = 9
	save(late)
	if _, err := s.GetAccessBundle(ctx, tenant, bundleB.ID); !errors.Is(err, store.ErrAccessBundleNotFound) {
		t.Fatalf("deleted bundle after a late save: %v", err)
	}
	if list, err := s.ListAccessBundles(ctx, tenant, 10); err != nil || len(list) != 1 || list[0].ID != bundleA.ID {
		t.Fatalf("live bundles = %+v %v", list, err)
	}
	if _, allowed, err := s.RunAuthority(ctx, tenant, runID, now); err != nil || allowed != nil {
		t.Fatalf("run authority after its last bundle was deleted = %v %v", allowed, err)
	}

	// A user grant lives only while its member is active.
	const member = "dev@payments.example"
	if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		return s.ApplyTenantMemberUpsertedTx(ctx, tx, store.TenantMember{TenantID: tenant, Subject: member, DisplayName: "Dev",
			Roles: []string{"viewer"}, Source: "manual", Status: "active", CreatedAt: now, UpdatedAt: now, EventSequence: 1})
	}); err != nil {
		t.Fatal(err)
	}
	grant(bundleA.ID, "user", member, nil)
	if held, err := s.EffectiveAuthority(ctx, tenant, member, now); err != nil || len(held) != 3 {
		t.Fatalf("active member's authority = %+v %v", held, err)
	}
	offboardedAt := now.Add(time.Second)
	if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		return s.ApplyTenantMemberOffboardedTx(ctx, tx, store.TenantMember{TenantID: tenant, Subject: member, DisplayName: "Dev",
			Source: "manual", Status: "offboarded", CreatedAt: now, UpdatedAt: offboardedAt, OffboardedAt: &offboardedAt,
			OffboardedBy: "admin", OffboardReason: "left", EventSequence: 2})
	}); err != nil {
		t.Fatal(err)
	}
	if held, err := s.EffectiveAuthority(ctx, tenant, member, now); err != nil || len(held) != 0 {
		t.Fatalf("offboarded member's authority = %+v %v", held, err)
	}
	if live, err := s.LiveAccessBundleGrants(ctx, tenant, member, now); err != nil || len(live) != 0 {
		t.Fatalf("offboarded member's live grants = %+v %v", live, err)
	}

	// Applying the same event again (same ID) adds no activity row; ignored
	// events (the late revision, the late save of a deleted bundle) add none.
	revokeID := googleuuid.NewString()
	for range 2 {
		seq++
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplyAccessBundleRunRevokedTx(ctx, tx, tenant, runID, "admin", now, revokeID, seq)
		}); err != nil {
			t.Fatal(err)
		}
	}
	activity, err := s.ListAccessBundleActivity(ctx, tenant, store.AccessBundleActivityFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, a := range activity {
		count[a.Action]++
	}
	want := map[string]int{"saved": 3, "granted": 4, "run_issued": 1, "ungranted": 1, "deleted": 1, "run_revoked": 1}
	for action, n := range want {
		if count[action] != n {
			t.Fatalf("activity %s = %d, want %d (all: %v)", action, count[action], n, count)
		}
	}
	// Search and paging: newest first, a cursor resumes after the last row.
	found, err := s.ListAccessBundleActivity(ctx, tenant, store.AccessBundleActivityFilter{Query: "DEPLOY #7", Limit: 10})
	if err != nil || len(found) != 1 || found[0].Action != "run_issued" || found[0].RunID != runID {
		t.Fatalf("search = %+v %v", found, err)
	}
	first, err := s.ListAccessBundleActivity(ctx, tenant, store.AccessBundleActivityFilter{Limit: 4})
	if err != nil || len(first) != 4 {
		t.Fatalf("first page = %d %v", len(first), err)
	}
	at, seqAt, err := store.ParseAccessBundleActivityCursor(store.AccessBundleActivityCursor(first[3]))
	if err != nil {
		t.Fatal(err)
	}
	rest, err := s.ListAccessBundleActivity(ctx, tenant, store.AccessBundleActivityFilter{BeforeAt: &at, BeforeSequence: seqAt, Limit: 100})
	if err != nil || len(first)+len(rest) != len(activity) {
		t.Fatalf("pages %d + %d, want %d: %v", len(first), len(rest), len(activity), err)
	}
	for _, bad := range []string{"", "x|1", time.Now().Format(time.RFC3339Nano) + "|0"} {
		if _, _, err := store.ParseAccessBundleActivityCursor(bad); err == nil {
			t.Fatalf("cursor %q parsed", bad)
		}
	}
}
