// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A251: bundles, grants, runs and their activity come back the same from a
// cold snapshot and from an event-only rebuild, and a grant removed after the
// snapshot stays removed in both.
func TestAccessBundlesSurviveSnapshotAndEventRebuildA251(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)
	appendJSON := func(typ string, v any) {
		t.Helper()
		payload, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		mustAppend(t, log, events.Event{Type: typ, TenantID: tenantA, Data: payload})
	}
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("A251 recovery")})
	bundleID, grantID, runID := googleuuid.NewString(), googleuuid.NewString(), googleuuid.NewString()
	appendJSON(projections.EventAccessBundleSaved, projections.AccessBundleSaved{ID: bundleID, Name: "ci-deploy",
		Permissions: []string{"certs:read", "owners:read"}, Audiences: []string{"ci"}, MaxRunTTLSeconds: 900, Revision: 1, SavedBy: "admin"})
	appendJSON(projections.EventAccessBundleGranted, projections.AccessBundleGranted{ID: grantID, BundleID: bundleID,
		PrincipalType: "machine", Principal: "ci:deploy", GrantedBy: "admin"})
	appendJSON(projections.EventAccessBundleRunIssued, projections.AccessBundleRunIssued{ID: runID, Principal: "ci:deploy",
		BundleIDs: []string{bundleID}, GrantIDs: []string{grantID}, Permissions: []string{"certs:read", "owners:read"},
		Label: "deploy #1", ExpiresAt: time.Now().Add(time.Hour).UTC(), IssuedBy: "ci:deploy"})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	verify := func(wantAllowed []string, wantActivity []string) {
		t.Helper()
		if b, err := s.GetAccessBundle(ctx, tenantA, bundleID); err != nil || b.Name != "ci-deploy" || b.Revision != 1 {
			t.Fatalf("bundle = %+v %v", b, err)
		}
		run, allowed, err := s.RunAuthority(ctx, tenantA, runID, time.Now())
		if err != nil || run.Label != "deploy #1" || !slices.Equal(run.BundleIDs, []string{bundleID}) || !slices.Equal(allowed, wantAllowed) {
			t.Fatalf("run = %+v allowed=%v err=%v", run, allowed, err)
		}
		activity, err := s.ListAccessBundleActivity(ctx, tenantA, store.AccessBundleActivityFilter{Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		var actions []string
		for _, a := range activity {
			actions = append(actions, a.Action)
		}
		if !slices.Equal(actions, wantActivity) {
			t.Fatalf("activity = %v, want %v", actions, wantActivity)
		}
	}
	verify([]string{"certs:read", "owners:read"}, []string{"run_issued", "granted", "saved"})
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	appendJSON(projections.EventAccessBundleUngranted, projections.AccessBundleUngranted{ID: grantID, BundleID: bundleID,
		RemovedBy: "admin", Reason: "rotated"})
	truncateReadModelAndCheckpoint(t, s)
	restored, err := p.RestoreFromSnapshot(ctx, log)
	if err != nil || !restored {
		t.Fatalf("snapshot restore=%v err=%v", restored, err)
	}
	after := []string{"ungranted", "run_issued", "granted", "saved"}
	verify(nil, after)
	if err := s.DeleteAllSnapshots(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	verify(nil, after)
}
