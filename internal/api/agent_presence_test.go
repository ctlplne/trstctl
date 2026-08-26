// SPDX-License-Identifier: MPL-2.0

package api

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestAgentPresenceUsesTheServedHeartbeatContract(t *testing.T) {
	now := time.Date(2026, 8, 26, 6, 30, 0, 0, time.UTC)
	interval := 30 * time.Second
	boundary := now.Add(-2 * interval)
	stale := boundary.Add(-time.Nanosecond)
	future := now.Add(interval + time.Nanosecond)
	offboardedAt := now.Add(-time.Hour)

	tests := []struct {
		name     string
		agent    store.Agent
		state    string
		online   bool
		freshEnd bool
	}{
		{name: "active at exact freshness boundary", agent: store.Agent{Status: "active", LastSeenAt: &boundary}, state: agentPresenceOnline, online: true, freshEnd: true},
		{name: "degraded but connected", agent: store.Agent{Status: "degraded", LastSeenAt: &boundary}, state: agentPresenceOnline, online: true, freshEnd: true},
		{name: "one nanosecond stale", agent: store.Agent{Status: "active", LastSeenAt: &stale}, state: agentPresenceStale, freshEnd: true},
		{name: "no observation", agent: store.Agent{Status: "active"}, state: agentPresenceUnreported},
		{name: "offboarded beats a fresh observation", agent: store.Agent{Status: "offboarded", LastSeenAt: &now}, state: agentPresenceOffboarded},
		{name: "offboarding receipt beats a stale active lifecycle", agent: store.Agent{Status: "active", LastSeenAt: &now, OffboardedAt: &offboardedAt}, state: agentPresenceOffboarded},
		{name: "impossible future observation", agent: store.Agent{Status: "active", LastSeenAt: &future}, state: agentPresenceClockSkew},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := agentPresenceFor(tt.agent, now, interval)
			if got.State != tt.state || got.Online != tt.online {
				t.Fatalf("presence = %+v, want state=%q online=%t", got, tt.state, tt.online)
			}
			if (got.FreshUntil != nil) != tt.freshEnd {
				t.Fatalf("fresh_until = %v, want present=%t", got.FreshUntil, tt.freshEnd)
			}
			if got.EvaluatedAt != now.Format(time.RFC3339Nano) || got.Detail == "" {
				t.Fatalf("presence lacks evaluated_at/detail: %+v", got)
			}
		})
	}
}

func TestAgentPresencePreservesReceiptPrecision(t *testing.T) {
	now := time.Date(2026, 8, 26, 6, 30, 0, 987654321, time.UTC)
	lastSeen := now.Add(-15*time.Second - 123*time.Nanosecond)
	got := agentPresenceFor(store.Agent{Status: "active", LastSeenAt: &lastSeen}, now, 15*time.Second)
	if got.EvaluatedAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("evaluated_at = %q, want %q", got.EvaluatedAt, now.Format(time.RFC3339Nano))
	}
	wantFreshUntil := lastSeen.Add(30 * time.Second).Format(time.RFC3339Nano)
	if got.FreshUntil == nil || *got.FreshUntil != wantFreshUntil {
		t.Fatalf("fresh_until = %v, want %q", got.FreshUntil, wantFreshUntil)
	}
}

func TestAgentPresenceDefaultsToTheChannelInterval(t *testing.T) {
	now := time.Date(2026, 8, 26, 6, 30, 0, 0, time.UTC)
	lastSeen := now.Add(-2 * defaultAgentPresenceHeartbeatInterval)
	got := agentPresenceFor(store.Agent{Status: "active", LastSeenAt: &lastSeen}, now, 0)
	if !got.Online || got.State != agentPresenceOnline {
		t.Fatalf("default-interval presence = %+v, want online at the exact two-interval boundary", got)
	}
}
