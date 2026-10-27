// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A191: an agent's newest role grant wins by stream order, starts pending, and
// is marked applied only by the renewal that signed that grant; a grant
// recorded after the renewal began stays pending. Grants stay with their tenant.
func TestAgentRoleGrantsFollowStreamOrderAndTheRenewalThatSignedThem(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenantA = "a1910000-0000-4000-8000-000000000001"
	const tenantB = "b1910000-0000-4000-8000-000000000002"
	const agentID = "a1910000-0000-4000-8000-0000000000aa"
	seedTenant(t, s, tenantA)
	seedTenant(t, s, tenantB)
	at := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	apply := func(g store.AgentRoleGrant) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyAgentRolesGrantedTx(ctx, tx, g) })
	}
	markApplied := func(eventID, serial string) {
		t.Helper()
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyAgentRoleGrantAppliedTx(ctx, tx, tenantA, agentID, eventID, serial, at.Add(time.Hour))
		}); err != nil {
			t.Fatal(err)
		}
	}
	read := func() store.AgentRoleGrant {
		t.Helper()
		g, found, err := s.AgentRoleGrant(ctx, tenantA, agentID)
		if err != nil || !found {
			t.Fatalf("grant = %+v, %v, %v", g, found, err)
		}
		return g
	}

	relay := store.AgentRoleGrant{
		TenantID: tenantA, AgentID: agentID, Roles: []string{"host", "network"},
		GrantedAt: at, EventID: "ev-relay", EventSeq: 10,
	}
	if err := apply(relay); err != nil {
		t.Fatal(err)
	}
	if g := read(); !g.Pending() || !slices.Equal(g.Roles, relay.Roles) || g.EventID != "ev-relay" || !g.GrantedAt.Equal(at) {
		t.Fatalf("recorded grant = %+v", g)
	}
	older := relay
	older.Roles, older.EventID, older.EventSeq = []string{"host"}, "ev-older", 5
	if err := apply(older); err != nil {
		t.Fatal(err)
	}
	if g := read(); g.EventID != "ev-relay" {
		t.Fatalf("an older grant projected later replaced the newer one: %+v", g)
	}

	markApplied("ev-older", "01")
	if g := read(); !g.Pending() {
		t.Fatalf("a renewal of another grant applied this one: %+v", g)
	}
	markApplied("ev-relay", "0a1b")
	if g := read(); g.Pending() || g.AppliedSerial != "0a1b" || !g.AppliedAt.Equal(at.Add(time.Hour)) {
		t.Fatalf("the signing renewal did not apply the grant: %+v", g)
	}

	hostOnly := relay
	hostOnly.Roles, hostOnly.EventID, hostOnly.EventSeq = []string{"host"}, "ev-host", 20
	if err := apply(hostOnly); err != nil {
		t.Fatal(err)
	}
	if g := read(); !g.Pending() || g.AppliedSerial != "" || !slices.Equal(g.Roles, []string{"host"}) {
		t.Fatalf("a newer grant did not start pending: %+v", g)
	}
	markApplied("ev-relay", "0c0d")
	if g := read(); !g.Pending() {
		t.Fatalf("a renewal that signed the replaced grant applied the newer one: %+v", g)
	}

	if g, found, err := s.AgentRoleGrant(ctx, tenantB, agentID); err != nil || found {
		t.Fatalf("tenant B sees tenant A's grant: %+v, %v, %v", g, found, err)
	}
	if got, err := s.AgentRoleGrants(ctx, tenantA, []string{agentID, "a1910000-0000-4000-8000-0000000000bb"}); err != nil || len(got) != 1 || got[agentID].EventID != "ev-host" {
		t.Fatalf("grants by agent = %+v, %v", got, err)
	}
	if got, err := s.AgentRoleGrants(ctx, tenantB, []string{agentID}); err != nil || len(got) != 0 {
		t.Fatalf("tenant B's grants by agent = %+v, %v", got, err)
	}
	for name, bad := range map[string]store.AgentRoleGrant{
		"no stream sequence": {TenantID: tenantA, AgentID: agentID, Roles: []string{"host"}, GrantedAt: at, EventID: "ev-x"},
		"no roles":           {TenantID: tenantA, AgentID: agentID, GrantedAt: at, EventID: "ev-y", EventSeq: 30},
	} {
		if err := apply(bad); err == nil {
			t.Errorf("a grant with %s was projected", name)
		}
	}
}
