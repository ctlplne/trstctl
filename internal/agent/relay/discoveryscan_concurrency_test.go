// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
)

// A cold-start relay scans several listeners at once. Every successful probe
// must have one finding, or the control plane refuses the signed report and
// the agent's durable pending report blocks all later work.
func TestConcurrentTLSSweepProducesCompleteAcceptableReport(t *testing.T) {
	const listenerCount = 24
	servers := make([]*httptest.Server, 0, listenerCount)
	targets := make([]string, 0, listenerCount)
	for range listenerCount {
		server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		servers = append(servers, server)
		targets = append(targets, strings.TrimPrefix(server.URL, "https://"))
	}
	defer func() {
		for _, server := range servers {
			server.Close()
		}
	}()

	intent := relay.DiscoveryScanIntent{
		Execution:         segmentscan.ExecutionRelay,
		Mode:              relay.DiscoveryModeTLS,
		Targets:           targets,
		AllowLoopback:     true,
		RequiredAgentRole: segmentscan.RequiredRoleNetwork,
	}
	for attempt := 0; attempt < 3; attempt++ {
		report, err := relay.Sweep(context.Background(), intent)
		if err != nil {
			t.Fatalf("sweep %d: %v", attempt, err)
		}
		if report.Discovered != listenerCount || len(report.Findings) != listenerCount {
			t.Fatalf("sweep %d discovered=%d findings=%d, want %d each", attempt, report.Discovered, len(report.Findings), listenerCount)
		}
		if err := segmentscan.ValidateReport(intent, report); err != nil {
			t.Fatalf("sweep %d produced a report the control plane refuses: %v", attempt, err)
		}
	}
}
