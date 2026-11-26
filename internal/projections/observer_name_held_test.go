// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// TestObserverUnderAHeldNameAppliesAsTheNoOpItWasLiveLS1L1: an
// observer.registered event that names a name another of the tenant's
// observers holds (one appended before the command checked the name under
// the projection lock) failed its projection live. The catch-up and a
// rebuild apply it as that no-op, keeping the first observer, where both
// stopped at the (tenant, name) index; the first observer's later update
// still applies, and another tenant's observer may use the name.
func TestObserverUnderAHeldNameAppliesAsTheNoOpItWasLiveLS1L1(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	p := projections.New(s)
	const (
		first     = "1a5e0001-0000-4000-8000-000000000001"
		duplicate = "1a5e0001-0000-4000-8000-000000000002"
		theirs    = "1a5e0001-0000-4000-8000-000000000003"
	)
	observer := func(typ, tenant, id, name, eventsURL string) {
		t.Helper()
		data, err := json.Marshal(projections.ObserverRegistered{ID: id, Name: name, EventsURL: eventsURL,
			CredentialRef: "secret://observers/legacy", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		mustAppend(t, log, events.Event{Type: typ, TenantID: tenant, Data: data})
	}
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("LS-1-L1")})
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantB, Data: tenantRegistered("LS-1-L1 other")})
	observer(projections.EventObserverRegistered, tenantA, first, "edge-probe", "https://observer-a.example.test/events")
	observer(projections.EventObserverRegistered, tenantA, duplicate, "edge-probe", "https://observer-dup.example.test/events")
	observer(projections.EventObserverRegistered, tenantB, theirs, "edge-probe", "https://observer-b.example.test/events")
	observer(projections.EventObserverUpdated, tenantA, first, "edge-probe", "https://observer-a2.example.test/events")

	check := func(stage string) {
		t.Helper()
		got, err := s.GetExternalObserver(ctx, tenantA, first)
		if err != nil || got.Name != "edge-probe" || got.EventsURL != "https://observer-a2.example.test/events" ||
			got.CredentialRef != "secret://observers/legacy" || got.ConfiguredBy != "" {
			t.Fatalf("%s: the first observer = %+v %v, want it updated", stage, got, err)
		}
		if dup, err := s.GetExternalObserver(ctx, tenantA, duplicate); err == nil {
			t.Fatalf("%s: the duplicate projected an observer: %+v", stage, dup)
		}
		if other, err := s.GetExternalObserver(ctx, tenantB, theirs); err != nil || other.Name != "edge-probe" {
			t.Fatalf("%s: the other tenant's observer = %+v %v", stage, other, err)
		}
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("the catch-up stopped at the duplicate: %v", err)
	}
	check("catch-up")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("a log holding a pre-check duplicate does not rebuild: %v", err)
	}
	check("rebuild")
}
