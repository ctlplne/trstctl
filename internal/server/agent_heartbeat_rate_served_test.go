// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

func TestServedAgentHeartbeatBoundsBeforeAppend(t *testing.T) {
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, nil, withIsolatedTenant)
	for _, req := range []*transport.HeartbeatRequest{
		{Version: "1.0", Status: "active", Executors: &transport.ExecutorReport{Version: "1.0", HostProfileError: strings.Repeat("x", 513)}},
		{Version: "1.0", Status: "active", Executors: &transport.ExecutorReport{Version: "1.0", HostProfileError: strings.Repeat("x", agentMaxHeartbeatEventBytes)}},
	} {
		before, err := h.log.LastSequence(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		_, err = h.client.Heartbeat(t.Context(), req)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("oversized heartbeat status = %v", err)
		}
		after, err := h.log.LastSequence(t.Context())
		if err != nil || after != before {
			t.Fatalf("invalid heartbeat changed log head: before=%d after=%d err=%v", before, after, err)
		}
	}
	if _, err := h.client.Heartbeat(t.Context(), &transport.HeartbeatRequest{Version: "1.0", Status: "active"}); err != nil {
		t.Fatalf("valid heartbeat after rejections: %v", err)
	}
}

func TestServedAgentHeartbeatRateLimitPreventsAppend(t *testing.T) {
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, nil, withIsolatedTenant)
	for i := 0; i <= agentHeartbeatBurst; i++ {
		before, err := h.log.LastSequence(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		_, err = h.client.Heartbeat(t.Context(), &transport.HeartbeatRequest{Version: "1.0", Status: "active"})
		if i < agentHeartbeatBurst && err != nil {
			t.Fatalf("heartbeat %d within burst: %v", i+1, err)
		}
		if i == agentHeartbeatBurst && status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("heartbeat above burst status = %v", err)
		}
		after, readErr := h.log.LastSequence(t.Context())
		if readErr != nil {
			t.Fatal(readErr)
		}
		if i == agentHeartbeatBurst && after != before {
			t.Fatalf("throttled heartbeat appended an event: before=%d after=%d", before, after)
		}
	}
}
