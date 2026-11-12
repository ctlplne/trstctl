// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// OD-9: a standing approval approves a run's session request only for exactly
// its account and role, on a bundle the run's own live grants give and that
// still delegates that account and role, while the approval is unrevoked and
// unexpired and the run itself is live. Its uses are counted once per event,
// and the bundle's activity records the grant, each use and the revocation.
func TestAccessBundleStandingApprovalLookupOD9(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenant = "0d900000-0000-4000-8000-000000000009"
	seedTenant(t, s, tenant)
	now := time.Now().UTC().Truncate(time.Microsecond)
	seq := uint64(200)
	apply := func(fn func(tx pgx.Tx, eventID string, sequence uint64) error) string {
		t.Helper()
		seq++
		id := googleuuid.NewString()
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error { return fn(tx, id, seq) }); err != nil {
			t.Fatal(err)
		}
		return id
	}
	pg := store.AccessBundleTarget{TargetType: "postgres", TargetID: "orders-db", Roles: []string{"readonly", "readwrite"}}
	bundle := store.AccessBundle{ID: googleuuid.NewString(), Name: "report-agent", Permissions: []string{"access:sessions.open"},
		Audiences: []string{"custom_agent"}, MaxRunTTLSeconds: 3600, Revision: 1, CreatedBy: "admin", CreatedAt: now,
		AccessTargets: []store.AccessBundleTarget{pg}}
	other := store.AccessBundle{ID: googleuuid.NewString(), Name: "other-agent", Permissions: []string{"access:sessions.open"},
		Audiences: []string{"custom_agent"}, MaxRunTTLSeconds: 3600, Revision: 1, CreatedBy: "admin", CreatedAt: now,
		AccessTargets: []store.AccessBundleTarget{pg}}
	for _, b := range []store.AccessBundle{bundle, other} {
		apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
			return s.ApplyAccessBundleSavedTx(ctx, tx, tenant, b, eventID, sequence)
		})
	}
	grant := func(bundleID, principal string) string {
		g := store.AccessBundleGrant{ID: googleuuid.NewString(), BundleID: bundleID, PrincipalType: "machine", Principal: principal,
			GrantedBy: "admin", GrantedAt: now}
		apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
			return s.ApplyAccessBundleGrantedTx(ctx, tx, tenant, g, eventID, sequence)
		})
		return g.ID
	}
	issue := func(principal string, bundleIDs, grantIDs []string, expires time.Time) string {
		runID := googleuuid.NewString()
		apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
			return s.ApplyAccessBundleRunIssuedTx(ctx, tx, tenant, store.AccessBundleRun{ID: runID, Principal: principal,
				BundleIDs: bundleIDs, GrantIDs: grantIDs, Permissions: []string{"access:sessions.open"}, ExpiresAt: expires,
				IssuedBy: "admin", IssuedAt: now}, eventID, sequence)
		})
		return runID
	}
	gAgent := grant(bundle.ID, "agent-9")
	gOther := grant(other.ID, "agent-10")
	run := issue("agent-9", []string{bundle.ID}, []string{gAgent}, now.Add(time.Hour))
	otherRun := issue("agent-10", []string{other.ID}, []string{gOther}, now.Add(time.Hour))

	approval := store.AccessBundleStandingApproval{TenantID: tenant, ID: googleuuid.NewString(), BundleID: bundle.ID,
		TargetType: "postgres", TargetID: "orders-db", Role: "readonly", Reason: "nightly report", GrantedBy: "approver",
		GrantedAt: now, ExpiresAt: now.Add(24 * time.Hour)}
	grantedEvent := apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
		return s.ApplyAccessBundleStandingApprovalGrantedTx(ctx, tx, approval, eventID, sequence)
	})
	// A replay of the grant converges.
	if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		return s.ApplyAccessBundleStandingApprovalGrantedTx(ctx, tx, approval, grantedEvent, seq)
	}); err != nil {
		t.Fatal(err)
	}

	lookup := func(runID, targetID, role string, at time.Time) bool {
		t.Helper()
		got, ok, err := s.ActiveRunStandingApproval(ctx, tenant, runID, "postgres", targetID, role, at)
		if err != nil {
			t.Fatal(err)
		}
		if ok && got.ID != approval.ID {
			t.Fatalf("matched another approval: %+v", got)
		}
		return ok
	}
	if !lookup(run, "orders-db", "readonly", now) {
		t.Fatal("the run's approved account does not match")
	}
	for name, matched := range map[string]bool{
		"another role":                      lookup(run, "orders-db", "readwrite", now),
		"another account":                   lookup(run, "billing-db", "readonly", now),
		"another bundle's run":              lookup(otherRun, "orders-db", "readonly", now),
		"an unknown run":                    lookup(googleuuid.NewString(), "orders-db", "readonly", now),
		"after the approval expires":        lookup(run, "orders-db", "readonly", now.Add(25*time.Hour)),
		"after the run expires":             lookup(run, "orders-db", "readonly", now.Add(2*time.Hour)),
		"at the approval's expiry instant":  lookup(run, "orders-db", "readonly", approval.ExpiresAt),
		"another account in the same query": lookup(run, "orders-db", "", now),
	} {
		if matched {
			t.Errorf("%s matched the standing approval", name)
		}
	}

	// Uses count once per event, and record the run in the bundle's activity.
	use := func() string {
		return apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
			return s.ApplyAccessBundleStandingApprovalUsedTx(ctx, tx, tenant, approval.ID, run, "agent-9", "standing-approval:"+approval.ID, now, eventID, sequence)
		})
	}
	usedEvent := use()
	if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		return s.ApplyAccessBundleStandingApprovalUsedTx(ctx, tx, tenant, approval.ID, run, "agent-9", "standing-approval:"+approval.ID, now, usedEvent, seq)
	}); err != nil {
		t.Fatal(err)
	}
	use()
	got, err := s.GetAccessBundleStandingApproval(ctx, tenant, approval.ID)
	if err != nil || got.Approvals != 2 || got.LastApprovedAt == nil {
		t.Fatalf("after two uses and a replay: %+v %v", got, err)
	}

	// A bundle that no longer delegates the role approves nothing for it.
	narrowed := bundle
	narrowed.Revision = 2
	narrowed.AccessTargets = []store.AccessBundleTarget{{TargetType: "postgres", TargetID: "orders-db", Roles: []string{"readwrite"}}}
	apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
		return s.ApplyAccessBundleSavedTx(ctx, tx, tenant, narrowed, eventID, sequence)
	})
	if lookup(run, "orders-db", "readonly", now) {
		t.Fatal("a bundle that no longer delegates the role still matched")
	}
	apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
		restored := bundle
		restored.Revision = 3
		return s.ApplyAccessBundleSavedTx(ctx, tx, tenant, restored, eventID, sequence)
	})
	if !lookup(run, "orders-db", "readonly", now) {
		t.Fatal("the delegation is back but the approval does not match")
	}

	// The first revocation stands; the revoked approval matches nothing.
	apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
		return s.ApplyAccessBundleStandingApprovalRevokedTx(ctx, tx, tenant, approval.ID, "approver", "agent retired", now, eventID, sequence)
	})
	apply(func(tx pgx.Tx, eventID string, sequence uint64) error {
		return s.ApplyAccessBundleStandingApprovalRevokedTx(ctx, tx, tenant, approval.ID, "someone", "later", now.Add(time.Minute), eventID, sequence)
	})
	got, err = s.GetAccessBundleStandingApproval(ctx, tenant, approval.ID)
	if err != nil || got.RevokedAt == nil || got.RevokedBy != "approver" || got.RevokeReason != "agent retired" {
		t.Fatalf("after two revocations: %+v %v", got, err)
	}
	if lookup(run, "orders-db", "readonly", now) {
		t.Fatal("a revoked approval matched")
	}
	listed, err := s.ListAccessBundleStandingApprovals(ctx, tenant, bundle.ID)
	if err != nil || len(listed) != 1 || listed[0].ID != approval.ID {
		t.Fatalf("list = %+v %v", listed, err)
	}
	if listed, err := s.ListAccessBundleStandingApprovals(ctx, tenant, other.ID); err != nil || len(listed) != 0 {
		t.Fatalf("the other bundle's list = %+v %v", listed, err)
	}

	activity, err := s.ListAccessBundleActivity(ctx, tenant, store.AccessBundleActivityFilter{BundleID: bundle.ID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, a := range activity {
		counts[a.Action]++
		if a.Action == "standing_approval_used" && (a.RunID != run || a.Principal != "agent-9" || a.Actor != "standing-approval:"+approval.ID || a.Detail != "postgres/orders-db as readonly") {
			t.Errorf("a use's activity = %+v", a)
		}
	}
	if counts["standing_approval_granted"] != 1 || counts["standing_approval_used"] != 2 || counts["standing_approval_revoked"] != 1 {
		t.Fatalf("activity counts = %v", counts)
	}
}
