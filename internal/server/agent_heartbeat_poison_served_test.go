// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/projections"
)

// The request must pass the same event-shape checks as replay before it is
// appended. One malformed heartbeat otherwise poisons the shared log tail.
func TestMalformedExecutorHeartbeatNeverEntersEventLog(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleHost})
	ctx := context.Background()
	cases := []struct {
		name   string
		report transport.ExecutorReport
	}{
		{"duplicate kind", transport.ExecutorReport{Version: "v1", Kinds: []transport.ExecutorKind{{Kind: "deploy"}, {Kind: "deploy"}}}},
		{"oversized version", transport.ExecutorReport{Version: strings.Repeat("v", 129), Kinds: []transport.ExecutorKind{{Kind: "deploy"}}}},
		{"empty kind", transport.ExecutorReport{Version: "v1", Kinds: []transport.ExecutorKind{{Kind: " "}}}},
		{"oversized connector", transport.ExecutorReport{Version: "v1", Kinds: []transport.ExecutorKind{{Kind: "deploy", Connectors: []string{strings.Repeat("c", 129)}}}}},
	}
	for _, tc := range cases {
		before := servedEventCount(t, h.servedHarness, projections.EventAgentHeartbeat)
		_, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{
			AgentID: h.agent, Version: "v1", Status: "active", Executors: &tc.report,
		})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s: heartbeat error = %v, want InvalidArgument", tc.name, err)
		}
		if after := servedEventCount(t, h.servedHarness, projections.EventAgentHeartbeat); after != before {
			t.Fatalf("%s: malformed heartbeat appended %d events", tc.name, after-before)
		}
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "v1", Status: "active",
		Executors: &transport.ExecutorReport{Version: "v1", Kinds: []transport.ExecutorKind{{Kind: "deploy"}}},
	}); err != nil {
		t.Fatalf("valid executor heartbeat: %v", err)
	}
}
