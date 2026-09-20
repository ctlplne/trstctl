// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// The API keeps an older agent, a disabled relay, an unreachable relay, a
// degraded relay, and a fully healthy relay apart. They require five different
// operator actions; a boolean would make the topology lie in at least three of
// those cases.
func TestEnrollmentProxyStatusKeepsOperationalStatesApart(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 12, 14, 0, 0, 0, time.UTC)
	base := store.Agent{
		EnrollmentProxyReportedAt: &at,
		EnrollmentProxySegment:    "plant-7",
		EnrollmentProxyPublicURL:  "https://enrol.plant-7.example",
	}

	tests := []struct {
		name  string
		agent store.Agent
		want  string
	}{
		{name: "older agent", agent: store.Agent{}, want: enrollmentProxyUnreported},
		{name: "disabled", agent: base, want: enrollmentProxyNotServing},
		{name: "unverified", agent: withEnrollmentProxy(base, true, 0, 0, 2), want: enrollmentProxyUnverified},
		{name: "unreachable", agent: withEnrollmentProxy(base, true, 0, 2, 0), want: enrollmentProxyUnavailable},
		{name: "degraded", agent: withEnrollmentProxy(base, true, 1, 1, 0), want: enrollmentProxyDegraded},
		{name: "partly unverified", agent: withEnrollmentProxy(base, true, 1, 0, 1), want: enrollmentProxyDegraded},
		{name: "healthy", agent: withEnrollmentProxy(base, true, 2, 0, 0), want: enrollmentProxyServing},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := agentEnrollmentProxyFor(tc.agent)
			if got.State != tc.want {
				t.Fatalf("state = %q, want %q (%+v)", got.State, tc.want, got)
			}
			if got.Detail == "" {
				t.Fatal("state has no operator-facing explanation")
			}
		})
	}

	full := withEnrollmentProxy(base, true, 1, 1, 0)
	full.EnrollmentProxyForwarded = 41
	full.EnrollmentProxyRefused = 3
	full.EnrollmentProxyUpstreamFailures = 2
	full.EnrollmentProxyLastForwardedAt = &at
	full.EnrollmentProxyLastFailoverAt = &at
	got := agentEnrollmentProxyFor(full)
	if got.Segment != "plant-7" || got.PublicURL != "https://enrol.plant-7.example" ||
		got.ForwardedRequests != 41 || got.RefusedRequests != 3 || got.UpstreamFailures != 2 ||
		got.LastForwardedAt == "" || got.LastFailoverAt == "" || got.ReportedAt == "" {
		t.Fatalf("API dropped durable topology/failover evidence: %+v", got)
	}
}

func withEnrollmentProxy(a store.Agent, serving bool, healthy, unhealthy, unknown int) store.Agent {
	a.EnrollmentProxyServing = serving
	a.EnrollmentProxyHealthyUpstreams = healthy
	a.EnrollmentProxyUnhealthyUpstreams = unhealthy
	a.EnrollmentProxyUnknownUpstreams = unknown
	return a
}
