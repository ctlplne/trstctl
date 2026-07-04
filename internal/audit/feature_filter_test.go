// SPDX-License-Identifier: MPL-2.0

package audit_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/audit"
)

// TestAuditFeatureActionFilter is the COVER-008 acceptance for audit filtering by
// feature_id/action: an operator filters the trail by the catalog feature and action
// that produced a mutation, without naming raw event-type strings. It fails before
// the Query gained FeatureID/Action support (the resolver intersects the event types
// the ledger catalogues for the selector) and passes after.
//
// The log here mixes lifecycle and owner events for one tenant; the assertions prove
// the resolver narrows correctly in each direction (feature+action, feature-only),
// composes with the tenant scope (AN-1), and — critically — fails closed: a
// feature/action that catalogues no events returns zero records, never the
// unfiltered log.
func TestAuditFeatureActionFilter(t *testing.T) {
	log := openLog(t)
	ctx := context.Background()
	// F6 lifecycle: issued, deployed, revoked. F8 RBAC: owner.created. Plus a second
	// tenant's revoke that must never leak.
	appendEvent(t, log, tenantA, "identity.issued")
	appendEvent(t, log, tenantA, "identity.deployed")
	appendEvent(t, log, tenantA, "identity.revoked")
	appendEvent(t, log, tenantA, "owner.created")
	appendEvent(t, log, tenantB, "identity.revoked")

	svc := newService(t, log)

	// feature_id + action: only the one event type that action emits.
	recs, err := svc.Search(ctx, audit.Query{TenantID: tenantA, FeatureID: "F6", Action: "revoke"})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Type != "identity.revoked" {
		t.Fatalf("F6/revoke filter = %v, want one identity.revoked", recs)
	}
	if recs[0].TenantID != tenantA {
		t.Errorf("feature/action filter leaked tenant %s", recs[0].TenantID)
	}

	// action alone resolves across features (here only F6 uses "deploy").
	recs, err = svc.Search(ctx, audit.Query{TenantID: tenantA, Action: "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Type != "identity.deployed" {
		t.Fatalf("action=deploy filter = %v, want one identity.deployed", recs)
	}

	// feature alone resolves to every event type that feature's actions emit. F6
	// (lifecycle automation) covers deploy/renew/revoke/retire/create_identity — but
	// NOT issue, which is catalogued under F4 (CA-agnostic issuance). So of the three
	// lifecycle events present (issued, deployed, revoked), F6 matches deployed and
	// revoked; the issued event (F4) and the owner event (F8) do not.
	recs, err = svc.Search(ctx, audit.Query{TenantID: tenantA, FeatureID: "F6"})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("F6 feature filter = %d records, want 2 (deployed+revoked; issued is F4, owner is F8)", len(recs))
	}
	for _, r := range recs {
		if r.Type == "owner.created" || r.Type == "identity.issued" {
			t.Errorf("F6 filter wrongly included non-F6 event %s", r.Type)
		}
	}

	// F4 (issuance) catalogues identity.issued, so the issued event matches it and
	// the F6 deploy/revoke events do not — proving the feature taxonomy partitions
	// the lifecycle events across features rather than lumping them.
	recs, err = svc.Search(ctx, audit.Query{TenantID: tenantA, FeatureID: "F4", Action: "issue"})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Type != "identity.issued" {
		t.Fatalf("F4/issue filter = %v, want one identity.issued", recs)
	}

	// fail closed: a feature with no catalogued events returns nothing, NOT the
	// unfiltered log. This is the security-relevant case — an unknown selector must
	// never widen to "show everything".
	recs, err = svc.Search(ctx, audit.Query{TenantID: tenantA, FeatureID: "F999", Action: "bogus"})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("unknown feature/action filter = %d records, want 0 (must fail closed, not return the whole log)", len(recs))
	}
}

// TestAuditFeatureActionFilterComposesWithType proves the feature/action filter
// intersects with an explicit type filter rather than replacing it: an event must be
// both named in the type filter AND catalogued for the selector.
func TestAuditFeatureActionFilterComposesWithType(t *testing.T) {
	log := openLog(t)
	ctx := context.Background()
	appendEvent(t, log, tenantA, "identity.issued")
	appendEvent(t, log, tenantA, "identity.revoked")

	svc := newService(t, log)

	// type=identity.issued but action=revoke -> disjoint -> zero records.
	recs, err := svc.Search(ctx, audit.Query{
		TenantID: tenantA, Types: []string{"identity.issued"}, FeatureID: "F6", Action: "revoke",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("type+feature/action intersection (disjoint) = %d, want 0", len(recs))
	}

	// type=identity.revoked AND action=revoke -> agree -> one record.
	recs, err = svc.Search(ctx, audit.Query{
		TenantID: tenantA, Types: []string{"identity.revoked"}, FeatureID: "F6", Action: "revoke",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Type != "identity.revoked" {
		t.Fatalf("type+feature/action intersection (agree) = %v, want one identity.revoked", recs)
	}
}
